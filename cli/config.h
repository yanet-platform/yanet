#pragma once

#include <string>

namespace config
{

namespace decap
{

// allows @announceRaw for @prefixRaw in decap @module
void allow(const std::string& module,
           const std::string& prefixRaw,
           const std::string& announceRaw);

// disallows @announceRaw for @prefixRaw in decap @module
void disallow(const std::string& module,
              const std::string& prefixRaw,
              const std::string& announceRaw);

// removes @prefixRaw in decap @module
void remove(const std::string& module,
            const std::string& prefixRaw);

} /* namespace decap */

namespace nat64stateless
{

// allows @announceRaw for @prefixRaw in nat64stateless @module
void allow4(const std::string& module,
            const std::string& prefixRaw,
            const std::string& announceRaw);

// disallows @announceRaw for @prefixRaw in nat64stateless @module
void disallow4(const std::string& module,
               const std::string& prefixRaw,
               const std::string& announceRaw);

// removes @prefixRaw in nat64stateless @module
void remove4(const std::string& module,
             const std::string& prefixRaw);

// allows @announceRaw for @prefixRaw in nat64stateless @module
void allow6(const std::string& module,
            const std::string& prefixRaw,
            const std::string& announceRaw);

// disallows @announceRaw for @prefixRaw in nat64stateless @module
void disallow6(const std::string& module,
               const std::string& prefixRaw,
               const std::string& announceRaw);

// removes @prefixRaw in nat64stateless @module
void remove6(const std::string& module,
             const std::string& prefixRaw);

} /* namespace nat64stateless */

void reload();

} /* namespace config */
