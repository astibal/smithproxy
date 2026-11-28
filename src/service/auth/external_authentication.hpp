#pragma once

namespace sx::auth {

// Starts the Core-owned runtime credentials and local administrator
// authentication endpoint. A disabled management GUI is a process-level
// override for GUI and gateway credentials only; the local administrator
// socket remains available to SSH and other trusted local clients.
// Repeated calls are harmless.
void manage_external_authentication(bool gui_enabled = true);

// Stops every external authentication worker before configuration and crypto
// services are dismantled. Repeated calls are harmless.
void stop_external_authentication() noexcept;

} // namespace sx::auth
