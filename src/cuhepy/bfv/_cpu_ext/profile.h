// Opt-in, per-thread native timings. Nested scopes report exclusive time so
// transforms are not also charged to CRT reconstruction or key switching.
#pragma once
#include <array>
#include <chrono>
#include <cstdint>

namespace xtrace_bfv {
enum class Phase : std::size_t {
    forward_ntt, inverse_ntt, to_residues, crt_reconstruct, crt_exact_fallback, gadget_decompose,
    pointwise, scale_round, mod_q, buffers, automorphism, add_sub, wire_import, wire_export, rns_compose, rns_scale, other, count
};
inline constexpr const char* phase_names[] = {
    "forward_ntt", "inverse_ntt", "to_residues", "crt_reconstruct", "crt_exact_fallback", "gadget_decompose",
    "pointwise", "scale_round", "mod_q", "buffers", "automorphism", "add_sub", "wire_import", "wire_export", "rns_compose", "rns_scale", "other"
};
struct NativeProfile {
    using Clock = std::chrono::steady_clock;
    std::array<std::uint64_t, static_cast<std::size_t>(Phase::count)> ns{}, calls{};
    std::size_t current = static_cast<std::size_t>(Phase::other);
    Clock::time_point last;
    void tick() {
        auto now = Clock::now();
        ns[current] += std::chrono::duration_cast<std::chrono::nanoseconds>(now - last).count();
        last = now;
    }
};
inline thread_local NativeProfile* active_profile = nullptr;

class ProfileScope {
    NativeProfile* profile_ = active_profile;
    std::size_t parent_ = 0;
public:
    explicit ProfileScope(Phase phase) {
        if (profile_) {
            profile_->tick();
            parent_ = profile_->current;
            profile_->current = static_cast<std::size_t>(phase);
            ++profile_->calls[profile_->current];
        }
    }
    ~ProfileScope() {
        if (!profile_) return;
        profile_->tick();
        profile_->current = parent_;
    }
    ProfileScope(const ProfileScope&) = delete;
    ProfileScope& operator=(const ProfileScope&) = delete;
};

class ProfileSession {
    NativeProfile* previous_profile_ = active_profile;
public:
    explicit ProfileSession(NativeProfile& profile) {
        active_profile = &profile;
        profile.last = NativeProfile::Clock::now();
    }
    ~ProfileSession() { active_profile = previous_profile_; }
    ProfileSession(const ProfileSession&) = delete;
    ProfileSession& operator=(const ProfileSession&) = delete;
};
} // namespace xtrace_bfv
