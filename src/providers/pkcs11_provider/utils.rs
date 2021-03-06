// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use super::Pkcs11Provider;
use log::error;
use log::{info, trace, warn};
use parsec_interface::requests::ResponseStatus;
use parsec_interface::requests::Result;
use pkcs11::errors::Error;
use pkcs11::types::*;
use pkcs11::types::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER};

/// Convert the PKCS 11 library specific error values to ResponseStatus values that are returned on
/// the wire protocol
///
/// Most of them are PsaErrorCommunicationFailure as, in the general case, the calls to the PKCS11
/// library should suceed with the values crafted by the provider.
/// If an error happens in the PKCS11 library, it means that it was badly used by the provider or
/// that it failed in an unexpected way and hence the PsaErrorCommunicationFailure error.
/// The errors translated to response status are related with signature verification failure, lack
/// of memory, hardware failure, corruption detection, lack of entropy and unsupported operations.
pub fn to_response_status(error: Error) -> ResponseStatus {
    match error {
        Error::Io(e) => ResponseStatus::from(e),
        Error::Module(e) | Error::InvalidInput(e) => {
            format_error!("Conversion of error to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
        Error::Pkcs11(ck_rv) => rv_to_response_status(ck_rv),
    }
}

pub fn rv_to_response_status(rv: CK_RV) -> ResponseStatus {
    match rv {
        CKR_OK => ResponseStatus::Success,
        CKR_HOST_MEMORY => ResponseStatus::PsaErrorInsufficientMemory,
        CKR_DEVICE_ERROR => ResponseStatus::PsaErrorHardwareFailure,
        CKR_DEVICE_MEMORY => ResponseStatus::PsaErrorInsufficientStorage,
        CKR_DEVICE_REMOVED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_SIGNATURE_INVALID => ResponseStatus::PsaErrorInvalidSignature,
        CKR_SIGNATURE_LEN_RANGE => ResponseStatus::PsaErrorInvalidSignature,
        CKR_TOKEN_NOT_PRESENT => ResponseStatus::PsaErrorHardwareFailure,
        CKR_TOKEN_NOT_RECOGNIZED => ResponseStatus::PsaErrorHardwareFailure,
        CKR_RANDOM_NO_RNG => ResponseStatus::PsaErrorInsufficientEntropy,
        CKR_STATE_UNSAVEABLE => ResponseStatus::PsaErrorHardwareFailure,
        s @ CKR_CURVE_NOT_SUPPORTED
        | s @ CKR_DOMAIN_PARAMS_INVALID
        | s @ CKR_FUNCTION_NOT_SUPPORTED => {
            if crate::utils::GlobalConfig::log_error_details() {
                error!("Not supported value ({:?})", s);
            }
            ResponseStatus::PsaErrorNotSupported
        }
        e => {
            format_error!("Error converted to PsaErrorCommunicationFailure", e);
            ResponseStatus::PsaErrorCommunicationFailure
        }
    }
}

// For PKCS 11, a key pair consists of two independant public and private keys. Both will share the
// same key ID.
pub enum KeyPairType {
    PublicKey,
    PrivateKey,
    Any,
}

// Representation of a PKCS 11 session.
pub struct Session<'a> {
    provider: &'a Pkcs11Provider,
    session_handle: CK_SESSION_HANDLE,
    // This information is necessary to log out when dropped.
    is_logged_in: bool,
}

#[derive(PartialEq)]
pub enum ReadWriteSession {
    ReadOnly,
    ReadWrite,
}

impl Session<'_> {
    pub fn new(provider: &Pkcs11Provider, read_write: ReadWriteSession) -> Result<Session> {
        if crate::utils::GlobalConfig::log_error_details() {
            info!("Opening session on slot {}", provider.slot_number);
        }

        let mut session_flags = CKF_SERIAL_SESSION;
        if read_write == ReadWriteSession::ReadWrite {
            session_flags |= CKF_RW_SESSION;
        }

        trace!("OpenSession command");
        match provider
            .backend
            .open_session(provider.slot_number, session_flags, None, None)
        {
            Ok(session_handle) => {
                let mut session = Session {
                    provider,
                    session_handle,
                    is_logged_in: false,
                };

                // The stress tests revealed bugs when sessions were concurrently running and some
                // of them where logging in and out during their execution. These bugs seemed to
                // disappear when *all* sessions are logged in by default.
                // See https://github.com/opendnssec/SoftHSMv2/issues/509 for reference.
                // This has security implications and should be disclosed.
                session.login()?;

                Ok(session)
            }
            Err(e) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Error opening session for slot {}; error: {}.",
                        provider.slot_number, e
                    );
                } else {
                    error!("Error opening session for slot {}", provider.slot_number);
                }
                Err(to_response_status(e))
            }
        }
    }

    pub fn session_handle(&self) -> CK_SESSION_HANDLE {
        self.session_handle
    }

    fn login(&mut self) -> Result<()> {
        #[allow(clippy::mutex_atomic)]
        let mut logged_sessions_counter = self
            .provider
            .logged_sessions_counter
            .lock()
            .expect("Error while locking mutex.");

        if self.is_logged_in {
            if crate::utils::GlobalConfig::log_error_details() {
                info!(
                    "This session ({}) has already requested authentication.",
                    self.session_handle
                );
            }
            Ok(())
        } else if *logged_sessions_counter > 0 {
            info!(
                "Logging in ignored as {} sessions are already requiring authentication.",
                *logged_sessions_counter
            );
            *logged_sessions_counter += 1;
            self.is_logged_in = true;
            Ok(())
        } else if let Some(user_pin) = self.provider.user_pin.as_ref() {
            trace!("Login command");
            match self
                .provider
                .backend
                .login(self.session_handle, CKU_USER, Some(user_pin))
            {
                Ok(_) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        info!("Logging in session {}.", self.session_handle);
                    }
                    *logged_sessions_counter += 1;
                    self.is_logged_in = true;
                    Ok(())
                }
                Err(e) => {
                    format_error!("Login operation failed", e);
                    Err(to_response_status(e))
                }
            }
        } else {
            warn!("Authentication requested but the provider has no user pin set!");
            Ok(())
        }
    }

    fn logout(&mut self) -> Result<()> {
        #[allow(clippy::mutex_atomic)]
        let mut logged_sessions_counter = self
            .provider
            .logged_sessions_counter
            .lock()
            .expect("Error while locking mutex.");

        if !self.is_logged_in {
            if crate::utils::GlobalConfig::log_error_details() {
                info!("Session {} has already logged out.", self.session_handle);
            }
            Ok(())
        } else if *logged_sessions_counter == 0 {
            info!("The user is already logged out, ignoring.");
            Ok(())
        } else if *logged_sessions_counter == 1 {
            // Only this session requires authentication.
            trace!("Logout command");
            match self.provider.backend.logout(self.session_handle) {
                Ok(_) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        info!("Logged out in session {}.", self.session_handle);
                    }
                    *logged_sessions_counter -= 1;
                    self.is_logged_in = false;
                    Ok(())
                }
                Err(e) => {
                    if crate::utils::GlobalConfig::log_error_details() {
                        error!(
                            "Failed to log out from session {} due to error {}. Continuing...",
                            self.session_handle, e
                        );
                    } else {
                        error!("Failed to log out from session. Continuing...");
                    }
                    Err(to_response_status(e))
                }
            }
        } else {
            info!(
                "{} sessions are still requiring authentication, not logging out.",
                *logged_sessions_counter
            );
            *logged_sessions_counter -= 1;
            self.is_logged_in = false;
            Ok(())
        }
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if self.logout().is_err() {
            error!("Error while logging out. Continuing...");
        }
        trace!("CloseSession command");
        match self.provider.backend.close_session(self.session_handle) {
            Ok(_) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    info!("Session {} closed.", self.session_handle);
                }
            }
            // Treat this as best effort.
            Err(e) => {
                if crate::utils::GlobalConfig::log_error_details() {
                    error!(
                        "Failed to log out from session {} due to error {}. Continuing...",
                        self.session_handle, e
                    );
                } else {
                    error!("Failed to log out from session. Continuing...");
                }
            }
        }
    }
}
