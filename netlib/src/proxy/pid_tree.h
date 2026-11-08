#pragma once

// ------------------------------------------------------------------------------------------
// PID-based application matching for ProxiFyre.
//
// An appNames entry of the form "pid:1234" matches process 1234 AND all of its descendants
// (children, grandchildren, ...). This makes it possible to route several instances of the
// same executable (e.g. steam.exe in different sandboxes) through different proxies, which
// name/path matching cannot do.
//
// The process tree is taken from a Toolhelp snapshot that is cached for up to 1 s and is
// refreshed immediately (rate-limited) when a PID that is not yet in the snapshot asks to be
// matched, so freshly started processes (e.g. the game launched by Steam) are recognized on
// their first connection.
// ------------------------------------------------------------------------------------------

#include <tlhelp32.h>

#include <atomic>
#include <cwchar>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace proxy::pid_tree
{
    /**
     * @brief Parses an upper-cased "PID:<number>" pattern.
     * @return the root PID, or nullopt when @p app is not a PID pattern.
     */
    [[nodiscard]] inline std::optional<DWORD> parse_pid_pattern(const std::wstring& app)
    {
        static constexpr std::wstring_view prefix = L"PID:";

        if (app.size() <= prefix.size() || app.compare(0, prefix.size(), prefix) != 0)
            return std::nullopt;

        wchar_t* end = nullptr;
        const unsigned long value = std::wcstoul(app.c_str() + prefix.size(), &end, 10);

        if (end == nullptr || *end != L'\0' || value == 0)
            return std::nullopt;

        return static_cast<DWORD>(value);
    }

    class process_tree_cache
    {
    public:
        static process_tree_cache& instance()
        {
            static process_tree_cache cache;
            return cache;
        }

        /**
         * @brief true when @p pid is @p root_pid or one of its descendants.
         */
        [[nodiscard]] bool is_in_tree(const DWORD pid, const DWORD root_pid)
        {
            if (pid == root_pid)
                return true;

            if (pid == 0 || root_pid == 0)
                return false;

            refresh(stale_after_ms);

            auto result = walk(pid, root_pid);

            // The process is newer than the snapshot: take a fresh one and try again.
            if (result == walk_result::unknown)
            {
                refresh(forced_min_interval_ms);
                result = walk(pid, root_pid);
            }

            return result == walk_result::found;
        }

    private:
        struct process_entry
        {
            DWORD parent_id;
            ULONGLONG create_time;  // 0 when it could not be queried
        };

        enum class walk_result : uint8_t { found, not_found, unknown };

        static constexpr ULONGLONG stale_after_ms = 1000;
        static constexpr ULONGLONG forced_min_interval_ms = 100;
        static constexpr int max_depth = 64;

        process_tree_cache() = default;

        [[nodiscard]] walk_result walk(DWORD pid, const DWORD root_pid) const
        {
            std::shared_lock lock(entries_mutex_);

            auto it = entries_.find(pid);
            if (it == entries_.end())
                return walk_result::unknown;

            for (int depth = 0; depth < max_depth; ++depth)
            {
                const DWORD parent = it->second.parent_id;

                if (parent == 0 || parent == pid)
                    return walk_result::not_found;

                const auto parent_it = entries_.find(parent);
                if (parent_it == entries_.end())
                    return walk_result::not_found;  // the parent has exited

                // PID-reuse guard: a real parent was started before its child. If the recorded
                // parent PID now belongs to a newer, unrelated process, stop here.
                if (it->second.create_time != 0 && parent_it->second.create_time != 0 &&
                    parent_it->second.create_time > it->second.create_time)
                    return walk_result::not_found;

                if (parent == root_pid)
                    return walk_result::found;

                pid = parent;
                it = parent_it;
            }

            return walk_result::not_found;
        }

        void refresh(const ULONGLONG min_age_ms)
        {
            if (GetTickCount64() - last_refresh_.load(std::memory_order_acquire) < min_age_ms)
                return;

            std::lock_guard refresh_lock(refresh_mutex_);

            // Another thread may have refreshed while we were waiting.
            if (GetTickCount64() - last_refresh_.load(std::memory_order_acquire) < min_age_ms)
                return;

            std::unordered_map<DWORD, process_entry> fresh;

            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (Process32FirstW(snapshot, &entry))
            {
                do
                {
                    fresh.emplace(entry.th32ProcessID,
                        process_entry{ entry.th32ParentProcessID, query_create_time(entry.th32ProcessID) });
                } while (Process32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);

            {
                std::unique_lock lock(entries_mutex_);
                entries_.swap(fresh);
            }

            last_refresh_.store(GetTickCount64(), std::memory_order_release);
        }

        [[nodiscard]] static ULONGLONG query_create_time(const DWORD pid)
        {
            const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (process == nullptr)
                return 0;

            FILETIME creation{}, exit{}, kernel{}, user{};
            ULONGLONG result = 0;

            if (GetProcessTimes(process, &creation, &exit, &kernel, &user))
                result = (static_cast<ULONGLONG>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;

            CloseHandle(process);
            return result;
        }

        mutable std::shared_mutex entries_mutex_;
        std::mutex refresh_mutex_;
        std::unordered_map<DWORD, process_entry> entries_;
        std::atomic<ULONGLONG> last_refresh_{ 0 };
    };
}
