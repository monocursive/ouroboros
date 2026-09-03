//! A mesh capability: JSON in, JSON out, state held by the instance.

use alloc::string::String;
use serde_json::Value;

use crate::describe::Describe;

/// A capability, on the shape `Ouroboros.Wasm.Capability` drives.
///
/// The wrapper agent forwards a mesh signal's body as JSON to [`Capability::handle`] and writes
/// the reply into its own state as `:last_answer`, which is what `Rollout.Probe`'s echo check
/// and `Rollout.Evaluation`'s expectation grammar read. So the reply is a document somebody
/// will match against, not a log line.
///
/// The instance is the `Self` value. It is created once by [`Capability::init`] and lives until
/// the host drops the instance; the SDK holds it in a single-threaded cell for you, so
/// `handle` gets `&mut self` and there is no static to declare.
///
/// # Never a trap
///
/// A body that is not JSON, a config that is not JSON and a message that arrived before `init`
/// are all `Err(String)` — a `guest_error` the host records against the instance, which stays
/// live. That is a different fact about a component than a trap, and this seam will not
/// manufacture the second when the first is what happened.
pub trait Capability: Sized {
    /// What this capability says about itself (contract C1). Called without an instance, so it
    /// cannot see the config; it is metadata, not state.
    fn describe() -> Describe;

    /// One instance, one config. Refusing here tells the host at `instantiate`, which is the
    /// point in the lifecycle where it can still do something about it.
    fn init(config: Value) -> Result<Self, String>;

    /// One message in, one reply out.
    fn handle(&mut self, body: Value) -> Result<Value, String>;
}

/// Exports a [`Capability`] as this component's implementation of the world.
///
/// One per component: it emits the `bindings::Guest` impl, the instance's state cell, the
/// wit-bindgen `export!`, and [`ceremony!`](crate::ceremony).
#[macro_export]
macro_rules! export_capability {
    ($ty:ident) => {
        static __OUROBOROS_STATE: $crate::__rt::State<::core::option::Option<$ty>> =
            $crate::__rt::State::new(::core::option::Option::None);

        struct __OuroborosGuest;

        impl $crate::bindings::Guest for __OuroborosGuest {
            fn describe() -> $crate::String {
                $crate::__rt::capability_describe::<$ty>()
            }

            fn init(config: $crate::String) -> ::core::result::Result<(), $crate::String> {
                $crate::__rt::capability_init::<$ty>(&__OUROBOROS_STATE, config)
            }

            fn handle_message(
                body: $crate::String,
            ) -> ::core::result::Result<$crate::String, $crate::String> {
                $crate::__rt::capability_handle::<$ty>(&__OUROBOROS_STATE, body)
            }
        }

        $crate::bindings::export_world!(__OuroborosGuest);
        $crate::ceremony!();
    };
}
