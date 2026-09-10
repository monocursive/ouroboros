# Loaded only by Playwright, after the test application boots.
Application.put_env(:ouroboros, :native_model_module, Ouroboros.Test.BrowserModel)
Application.put_env(:ouroboros, :native_model, "scripted:browser")
File.mkdir_p!(Path.join([File.cwd!(), "_build", "playwright-workspace"]))
