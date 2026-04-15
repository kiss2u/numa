//! Windows service wrapper.
//!
//! Lets the `numa.exe` binary act as a real Windows service registered with
//! the Service Control Manager (SCM). Invoked via `numa.exe --service` (the
//! form that `sc create … binPath=` uses).
//!
//! Interactive runs (`numa.exe`, `numa.exe run`, `numa.exe install`) do not
//! go through this module — they keep their existing console-attached
//! behaviour.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "Numa";

define_windows_service!(ffi_service_main, service_main);

/// Entry point the SCM hands control to after `StartServiceCtrlDispatcherW`.
/// Any panic here vanishes silently into the service host — log instead of
/// unwrapping.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("numa service exited with error: {:?}", e);
    }
}

fn run_service() -> windows_service::Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // TODO(windows-service): call numa's async serve loop here once main.rs's
    // server body is extracted into `numa::serve(config_path)`. For now the
    // service registers, reports Running, and blocks until SCM sends Stop —
    // useful for verifying the SCM plumbing end to end with `sc start Numa`
    // and `sc stop Numa`.
    let _ = shutdown_rx.recv();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Hand control to the SCM dispatcher. Blocks until the service stops.
/// Call only from the `--service` command path — interactive invocations
/// will hang here waiting for an SCM that isn't talking to them.
pub fn run_as_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}
