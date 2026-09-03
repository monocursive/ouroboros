//! The seam under the other three: the world's exports, as strings.

use alloc::string::String;

use crate::describe::Describe;

/// A component, stated at the width of the world itself: a `describe`, a config string, and a
/// reply that is whatever the author says it is.
///
/// [`Capability`](crate::Capability), [`Hook`](crate::Hook) and [`Check`](crate::Check) are all
/// this trait with a shape imposed on the strings. Implement `Raw` directly when the reply must
/// be stated **verbatim** — a `[checks]` failure is plain text, not JSON, and the acceptance
/// guest exists to be able to hand back an arbitrary string on demand. Everywhere else the JSON
/// traits are less to get wrong.
///
/// Neither method may trap. Both return `Err(String)`, which the helper reports as
/// `guest_error` and which leaves the instance live.
pub trait Raw: Sized {
    /// Metadata, as JSON. Pure: it reads nothing and changes nothing, and it is called without
    /// an instance, so it cannot see `init`'s config.
    fn describe() -> Describe;

    /// One instance, one config, once. The host's string, verbatim and unparsed.
    fn init(config: &str) -> Result<Self, String>;

    /// One message in, one reply out. State is this instance's, and it lives for as long as the
    /// instance does.
    fn handle(&mut self, body: &str) -> Result<String, String>;
}

/// The `Raw` seam, exported: a `bindings::Guest` impl over `$ty`, the instance's state cell, and
/// the ceremony.
///
/// One per component. See [`ceremony!`](crate::ceremony) for what the ceremony is.
#[macro_export]
macro_rules! export_raw {
    ($ty:ident) => {
        static __OUROBOROS_STATE: $crate::__rt::State<::core::option::Option<$ty>> =
            $crate::__rt::State::new(::core::option::Option::None);

        struct __OuroborosGuest;

        impl $crate::bindings::Guest for __OuroborosGuest {
            fn describe() -> $crate::String {
                $crate::__rt::raw_describe::<$ty>()
            }

            fn init(config: $crate::String) -> ::core::result::Result<(), $crate::String> {
                $crate::__rt::raw_init::<$ty>(&__OUROBOROS_STATE, config)
            }

            fn handle_message(
                body: $crate::String,
            ) -> ::core::result::Result<$crate::String, $crate::String> {
                $crate::__rt::raw_handle::<$ty>(&__OUROBOROS_STATE, body)
            }
        }

        $crate::bindings::export_world!(__OuroborosGuest);
        $crate::ceremony!();
    };
}
