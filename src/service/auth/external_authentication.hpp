#pragma once

namespace sx::auth {

// Starts the Core-owned runtime credentials and local administrator
// authentication endpoint. Repeated calls are harmless.
void manage_external_authentication();

// Stops every external authentication worker before configuration and crypto
// services are dismantled. Repeated calls are harmless.
void stop_external_authentication() noexcept;

} // namespace sx::auth
