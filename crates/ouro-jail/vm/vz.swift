// Experimental Linux VM transport. No host directories or IP network are
// attached during runs. The guest lease is driven by the calling process.
import Foundation
import Virtualization
import Darwin

func event(_ value: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

final class Runner: NSObject, VZVirtualMachineDelegate {
    var vm: VZVirtualMachine!
    var connection: VZVirtioSocketConnection?
    var inputSource: DispatchSourceRead?
    var socketSource: DispatchSourceRead?
    var custodySource: DispatchSourceRead?
    var signals: [DispatchSourceSignal] = []
    var input = Data()
    var stopping = false
    var started = Date()
    let bootstrap: Bool

    init(arguments: [String]) throws {
        guard arguments.count == 6 || (arguments.count == 5 && arguments[4] == "bootstrap") else {
            throw NSError(domain: "Usage: vz DISK SEED NVRAM CONSOLE bootstrap|run [CUSTODY_FD]", code: 2)
        }
        bootstrap = arguments[4] == "bootstrap"
        super.init()
        let config = VZVirtualMachineConfiguration()
        config.cpuCount = 2
        config.memorySize = 2 * 1024 * 1024 * 1024
        let boot = VZEFIBootLoader()
        let nvram = URL(fileURLWithPath: arguments[2])
        boot.variableStore = try VZEFIVariableStore(creatingVariableStoreAt: nvram)
        config.bootLoader = boot
        config.storageDevices = try [arguments[0], arguments[1]].enumerated().map { index, path in
            VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(
                url: URL(fileURLWithPath: path), readOnly: index == 1))
        }
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        let output = open(arguments[3], O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard output >= 0 else { throw POSIXError(.EIO) }
        console.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: nil,
            fileHandleForWriting: FileHandle(fileDescriptor: output, closeOnDealloc: true))
        config.serialPorts = [console]
        if bootstrap {
            let network = VZVirtioNetworkDeviceConfiguration()
            network.attachment = VZNATNetworkDeviceAttachment()
            config.networkDevices = [network]
        }
        try config.validate()
        vm = VZVirtualMachine(configuration: config)
        vm.delegate = self
        if arguments.count == 6 {
            guard let fd = Int32(arguments[5]), fd >= 3, fcntl(fd, F_GETFD) >= 0 else { throw POSIXError(.EBADF) }
            custodySource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
            custodySource!.setEventHandler { self.stop("custodian_lost") }
            custodySource!.resume()
        }
    }

    func stop(_ reason: String, code: Int32 = 125) {
        guard !stopping else { return }
        stopping = true
        event(["event": "stopping", "reason": reason])
        if vm.canStop {
            vm.stop { error in
                event(["event": "stopped", "error": error.map { String(describing: $0) } ?? ""])
                exit(error == nil ? code : 125)
            }
        } else { exit(code) }
    }

    func start() {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { exit(125) }
        let words = withUnsafeBytes(of: token) { Array($0.bindMemory(to: UInt32.self)) }
        event(["event": "owner", "pid": getpid(), "audit_token": words])
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { self.stop("signal", code: 128 + sig) }
            source.resume()
            signals.append(source)
        }
        signal(SIGPIPE, SIG_IGN)
        inputSource = DispatchSource.makeReadSource(fileDescriptor: STDIN_FILENO, queue: .main)
        inputSource!.setEventHandler {
            var bytes = [UInt8](repeating: 0, count: 65536)
            let count = read(STDIN_FILENO, &bytes, bytes.count)
            guard count > 0 else { self.stop("caller_eof"); return }
            self.input.append(contentsOf: bytes.prefix(count))
            guard self.input.count <= 4 * 1024 * 1024 else { self.stop("input_limit"); return }
            while let newline = self.input.firstIndex(of: 10) {
                let line = self.input.prefix(upTo: newline)
                self.input.removeSubrange(...newline)
                guard let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
                      let op = message["op"] as? String else { self.stop("bad_request"); return }
                if op == "stop" { self.stop("caller_stop", code: 0); return }
                guard op == "write", let encoded = message["data"] as? String,
                      let data = Data(base64Encoded: encoded), let conn = self.connection else {
                    self.stop("not_connected"); return
                }
                do { try FileHandle(fileDescriptor: conn.fileDescriptor, closeOnDealloc: false).write(contentsOf: data) }
                catch { self.stop("socket_write_failed"); return }
            }
        }
        inputSource!.resume()
        vm.start { result in
            switch result {
            case .failure(let error): event(["event": "error", "error": String(describing: error)]); exit(125)
            case .success:
                event(["event": "booted", "pid": getpid(), "network": self.bootstrap])
                self.connect()
            }
        }
    }

    func connect() {
        guard !stopping else { return }
        guard Date().timeIntervalSince(started) < (bootstrap ? 600 : 120) else { stop("boot_timeout"); return }
        let device = vm.socketDevices[0] as! VZVirtioSocketDevice
        device.connect(toPort: 1024) { result in
            switch result {
            case .failure:
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.connect() }
            case .success(let conn):
                self.connection = conn
                event(["event": "connected"])
                self.socketSource = DispatchSource.makeReadSource(fileDescriptor: conn.fileDescriptor, queue: .main)
                self.socketSource!.setEventHandler {
                    var bytes = [UInt8](repeating: 0, count: 65536)
                    let count = read(conn.fileDescriptor, &bytes, bytes.count)
                    guard count > 0 else { self.stop("guest_eof"); return }
                    event(["event": "data", "data": Data(bytes.prefix(count)).base64EncodedString()])
                }
                self.socketSource!.resume()
            }
        }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) { event(["event": "guest_stopped"]); exit(0) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        event(["event": "error", "error": String(describing: error)]); exit(125)
    }
}

do {
    let runner = try Runner(arguments: Array(CommandLine.arguments.dropFirst()))
    runner.start()
    withExtendedLifetime(runner) { RunLoop.main.run() }
} catch { event(["event": "error", "error": String(describing: error)]); exit(125) }
