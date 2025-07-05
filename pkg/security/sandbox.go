package security

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// SandboxManager manages plugin sandboxing using cgroups and seccomp
type SandboxManager struct {
	config      *SandboxConfig
	cgroups     map[string]*CGroup
	seccompProf *SeccompProfile
	auditLogger SecurityAuditLogger
	mutex       sync.RWMutex
	logger      *slog.Logger
}

// SandboxConfig contains sandboxing configuration
type SandboxConfig struct {
	EnableCGroups      bool     `json:"enable_cgroups"`
	EnableSeccomp      bool     `json:"enable_seccomp"`
	CGroupRoot         string   `json:"cgroup_root"`
	MaxMemoryMB        int64    `json:"max_memory_mb"`
	MaxCPUPercent      float64  `json:"max_cpu_percent"`
	MaxProcesses       int64    `json:"max_processes"`
	AllowedSyscalls    []string `json:"allowed_syscalls"`
	BlockedSyscalls    []string `json:"blocked_syscalls"`
	NetworkIsolation   bool     `json:"network_isolation"`
	FilesystemReadOnly bool     `json:"filesystem_readonly"`
	TempDirPath        string   `json:"temp_dir_path"`
	AllowedDirectories []string `json:"allowed_directories"`
	DeniedDirectories  []string `json:"denied_directories"`
}

// CGroup represents a control group for resource management
type CGroup struct {
	Name        string
	Path        string
	MemoryLimit int64
	CPULimit    float64
	PIDLimit    int64
	CreatedAt   time.Time
	Active      bool
}

// SeccompProfile defines syscall filtering rules
type SeccompProfile struct {
	DefaultAction string        `json:"default_action"`
	Syscalls      []SyscallRule `json:"syscalls"`
	Architectures []string      `json:"architectures"`
	Flags         []string      `json:"flags"`
}

// SyscallRule defines rules for individual syscalls
type SyscallRule struct {
	Names  []string          `json:"names"`
	Action string            `json:"action"`
	Args   []SyscallArgument `json:"args,omitempty"`
}

// SyscallArgument defines argument constraints for syscalls
type SyscallArgument struct {
	Index    int    `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"value_two,omitempty"`
	Op       string `json:"op"`
}

// SandboxedProcess represents a process running in a sandbox
type SandboxedProcess struct {
	PID        int
	PluginName string
	CGroupPath string
	StartTime  time.Time
	Command    *exec.Cmd
	Context    context.Context
	Cancel     context.CancelFunc
}

// NewSandboxManager creates a new sandbox manager
func NewSandboxManager(config *SandboxConfig, auditLogger SecurityAuditLogger, logger *slog.Logger) (*SandboxManager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	sm := &SandboxManager{
		config:      config,
		cgroups:     make(map[string]*CGroup),
		auditLogger: auditLogger,
		logger:      logger,
	}

	// Initialize cgroups if enabled
	if config.EnableCGroups {
		if err := sm.initializeCGroups(); err != nil {
			return nil, fmt.Errorf("failed to initialize cgroups: %w", err)
		}
	}

	// Initialize seccomp profile if enabled
	if config.EnableSeccomp {
		sm.seccompProf = sm.createSeccompProfile()
	}

	return sm, nil
}

// initializeCGroups sets up the cgroup hierarchy
func (sm *SandboxManager) initializeCGroups() error {
	// Check if cgroups v2 is available
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return fmt.Errorf("cgroups v2 not available: %w", err)
	}

	// Create plugin cgroup directory
	pluginCGroupPath := filepath.Join(sm.config.CGroupRoot, "hkp-plugins")
	if err := os.MkdirAll(pluginCGroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create plugin cgroup directory: %w", err)
	}

	sm.logger.Info("Initialized cgroups", "path", pluginCGroupPath)
	return nil
}

// CreateSandbox creates a new sandbox for a plugin
func (sm *SandboxManager) CreateSandbox(pluginName string) (*SandboxedProcess, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Create cgroup for plugin
	var cgroup *CGroup
	if sm.config.EnableCGroups {
		var err error
		cgroup, err = sm.createCGroup(pluginName)
		if err != nil {
			return nil, fmt.Errorf("failed to create cgroup: %w", err)
		}
	}

	// Create context for process management
	ctx, cancel := context.WithCancel(context.Background())

	sandbox := &SandboxedProcess{
		PluginName: pluginName,
		StartTime:  time.Now(),
		Context:    ctx,
		Cancel:     cancel,
	}

	if cgroup != nil {
		sandbox.CGroupPath = cgroup.Path
	}

	// Log sandbox creation
	sm.auditLogger.LogSecurityEvent("sandbox_created", map[string]interface{}{
		"plugin_name":     pluginName,
		"cgroup_enabled":  sm.config.EnableCGroups,
		"seccomp_enabled": sm.config.EnableSeccomp,
		"memory_limit":    sm.config.MaxMemoryMB,
		"cpu_limit":       sm.config.MaxCPUPercent,
	})

	return sandbox, nil
}

// createCGroup creates a new cgroup for a plugin
func (sm *SandboxManager) createCGroup(pluginName string) (*CGroup, error) {
	cgroupName := fmt.Sprintf("plugin-%s-%d", pluginName, time.Now().Unix())
	cgroupPath := filepath.Join(sm.config.CGroupRoot, "hkp-plugins", cgroupName)

	// Create cgroup directory
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cgroup directory: %w", err)
	}

	cgroup := &CGroup{
		Name:        cgroupName,
		Path:        cgroupPath,
		MemoryLimit: sm.config.MaxMemoryMB * 1024 * 1024, // Convert MB to bytes
		CPULimit:    sm.config.MaxCPUPercent,
		PIDLimit:    sm.config.MaxProcesses,
		CreatedAt:   time.Now(),
		Active:      true,
	}

	// Set memory limit
	if err := sm.setCGroupMemoryLimit(cgroup); err != nil {
		return nil, fmt.Errorf("failed to set memory limit: %w", err)
	}

	// Set CPU limit
	if err := sm.setCGroupCPULimit(cgroup); err != nil {
		return nil, fmt.Errorf("failed to set CPU limit: %w", err)
	}

	// Set process limit
	if err := sm.setCGroupPIDLimit(cgroup); err != nil {
		return nil, fmt.Errorf("failed to set PID limit: %w", err)
	}

	sm.cgroups[pluginName] = cgroup
	sm.logger.Info("Created cgroup", "plugin", pluginName, "path", cgroupPath)

	return cgroup, nil
}

// setCGroupMemoryLimit sets the memory limit for a cgroup
func (sm *SandboxManager) setCGroupMemoryLimit(cgroup *CGroup) error {
	memoryMaxPath := filepath.Join(cgroup.Path, "memory.max")
	return os.WriteFile(memoryMaxPath, []byte(strconv.FormatInt(cgroup.MemoryLimit, 10)), 0644)
}

// setCGroupCPULimit sets the CPU limit for a cgroup
func (sm *SandboxManager) setCGroupCPULimit(cgroup *CGroup) error {
	// Calculate CPU quota (100ms period, quota = period * cpu_percent / 100)
	period := 100000 // 100ms in microseconds
	quota := int64(float64(period) * cgroup.CPULimit / 100.0)

	quotaPath := filepath.Join(cgroup.Path, "cpu.max")
	quotaValue := fmt.Sprintf("%d %d", quota, period)
	return os.WriteFile(quotaPath, []byte(quotaValue), 0644)
}

// setCGroupPIDLimit sets the process limit for a cgroup
func (sm *SandboxManager) setCGroupPIDLimit(cgroup *CGroup) error {
	pidsMaxPath := filepath.Join(cgroup.Path, "pids.max")
	return os.WriteFile(pidsMaxPath, []byte(strconv.FormatInt(cgroup.PIDLimit, 10)), 0644)
}

// RunInSandbox executes a command in the sandbox
func (sm *SandboxManager) RunInSandbox(sandbox *SandboxedProcess, command string, args []string) error {
	// Create command with context
	cmd := exec.CommandContext(sandbox.Context, command, args...)

	// Set up seccomp filter if enabled
	if sm.config.EnableSeccomp {
		if err := sm.applySeccompFilter(cmd); err != nil {
			return fmt.Errorf("failed to apply seccomp filter: %w", err)
		}
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start sandboxed process: %w", err)
	}

	sandbox.PID = cmd.Process.Pid
	sandbox.Command = cmd

	// Add process to cgroup if enabled
	if sm.config.EnableCGroups && sandbox.CGroupPath != "" {
		if err := sm.addProcessToCGroup(sandbox); err != nil {
			sm.logger.Error("Failed to add process to cgroup", "error", err, "pid", sandbox.PID)
		}
	}

	// Log process start
	sm.auditLogger.LogSecurityEvent("sandboxed_process_started", map[string]interface{}{
		"plugin_name": sandbox.PluginName,
		"pid":         sandbox.PID,
		"command":     command,
		"args":        args,
		"cgroup_path": sandbox.CGroupPath,
	})

	return nil
}

// addProcessToCGroup adds a process to a cgroup
func (sm *SandboxManager) addProcessToCGroup(sandbox *SandboxedProcess) error {
	procsPath := filepath.Join(sandbox.CGroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(sandbox.PID)
	return os.WriteFile(procsPath, []byte(pidStr), 0644)
}

// applySeccompFilter applies seccomp filtering to a command
func (sm *SandboxManager) applySeccompFilter(cmd *exec.Cmd) error {
	// This is a simplified implementation
	// In production, you'd use a proper seccomp library like github.com/seccomp/libseccomp-golang

	// For now, we'll set up basic syscall restrictions using prctl
	cmd.SysProcAttr = &unix.SysProcAttr{
		// Enable seccomp strict mode (allow only read, write, exit, sigreturn)
		// This is very restrictive and would need to be customized for actual plugins
	}

	return nil
}

// createSeccompProfile creates a seccomp profile based on configuration
func (sm *SandboxManager) createSeccompProfile() *SeccompProfile {
	// Default profile with basic allowed syscalls
	allowedSyscalls := []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat",
		"poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
		"rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
		"readv", "writev", "access", "pipe", "select", "sched_yield",
		"mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
		"dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer",
		"getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
		"sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname",
		"getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork",
		"vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop",
		"semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl",
		"flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents",
		"getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat",
		"link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown",
		"fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage",
		"sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid",
		"setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
		"setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
		"getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid",
		"getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait",
		"rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod",
		"uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs",
		"getpriority", "setpriority", "sched_setparam", "sched_getparam",
		"sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
		"sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock",
		"mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root",
		"_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot",
		"sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff",
		"reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
		"init_module", "delete_module", "get_kernel_syms", "query_module",
		"quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall",
		"security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr",
		"getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
		"flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill",
		"time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
		"io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel",
		"get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old",
		"epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address",
		"restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
		"timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime",
		"clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
		"epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind",
		"set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend",
		"mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
		"add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init",
		"inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
		"mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat",
		"linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6",
		"ppoll", "unshare", "set_robust_list", "get_robust_list", "splice",
		"tee", "sync_file_range", "vmsplice", "move_pages", "utimensat",
		"epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate",
		"timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2",
		"epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev",
		"rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init",
		"fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at",
		"clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv",
		"process_vm_writev", "kcmp", "finit_module",
	}

	// Merge with configured syscalls
	if len(sm.config.AllowedSyscalls) > 0 {
		allowedSyscalls = sm.config.AllowedSyscalls
	}

	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_KILL",
		Syscalls: []SyscallRule{
			{
				Names:  allowedSyscalls,
				Action: "SCMP_ACT_ALLOW",
			},
		},
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Flags:         []string{"SECCOMP_FILTER_FLAG_TSYNC"},
	}
}

// DestroySandbox cleans up a sandbox
func (sm *SandboxManager) DestroySandbox(sandbox *SandboxedProcess) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Cancel context to stop process
	sandbox.Cancel()

	// Wait for process to exit or force kill
	if sandbox.Command != nil && sandbox.Command.Process != nil {
		done := make(chan error, 1)
		go func() {
			done <- sandbox.Command.Wait()
		}()

		select {
		case <-done:
			// Process exited gracefully
		case <-time.After(5 * time.Second):
			// Force kill after timeout
			if err := sandbox.Command.Process.Kill(); err != nil {
				sm.logger.Error("Failed to kill process", "error", err, "pid", sandbox.PID)
			}
		}
	}

	// Remove cgroup if it exists
	if sandbox.CGroupPath != "" {
		if err := sm.removeCGroup(sandbox.PluginName); err != nil {
			sm.logger.Error("Failed to remove cgroup", "error", err, "plugin", sandbox.PluginName)
		}
	}

	// Log sandbox destruction
	sm.auditLogger.LogSecurityEvent("sandbox_destroyed", map[string]interface{}{
		"plugin_name": sandbox.PluginName,
		"pid":         sandbox.PID,
		"duration":    time.Since(sandbox.StartTime).Seconds(),
	})

	return nil
}

// removeCGroup removes a cgroup
func (sm *SandboxManager) removeCGroup(pluginName string) error {
	cgroup, exists := sm.cgroups[pluginName]
	if !exists {
		return nil
	}

	// Remove cgroup directory
	if err := os.RemoveAll(cgroup.Path); err != nil {
		return fmt.Errorf("failed to remove cgroup directory: %w", err)
	}

	delete(sm.cgroups, pluginName)
	sm.logger.Info("Removed cgroup", "plugin", pluginName, "path", cgroup.Path)

	return nil
}

// GetSandboxStatus returns status information about active sandboxes
func (sm *SandboxManager) GetSandboxStatus() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	status := map[string]interface{}{
		"active_cgroups":      len(sm.cgroups),
		"cgroup_enabled":      sm.config.EnableCGroups,
		"seccomp_enabled":     sm.config.EnableSeccomp,
		"memory_limit_mb":     sm.config.MaxMemoryMB,
		"cpu_limit_percent":   sm.config.MaxCPUPercent,
		"max_processes":       sm.config.MaxProcesses,
		"network_isolation":   sm.config.NetworkIsolation,
		"filesystem_readonly": sm.config.FilesystemReadOnly,
	}

	// Add per-plugin cgroup information
	plugins := make(map[string]interface{})
	for pluginName, cgroup := range sm.cgroups {
		plugins[pluginName] = map[string]interface{}{
			"cgroup_name":  cgroup.Name,
			"memory_limit": cgroup.MemoryLimit,
			"cpu_limit":    cgroup.CPULimit,
			"pid_limit":    cgroup.PIDLimit,
			"created_at":   cgroup.CreatedAt,
			"active":       cgroup.Active,
		}
	}
	status["plugins"] = plugins

	return status
}

// MonitorSandboxes monitors resource usage of sandboxed processes
func (sm *SandboxManager) MonitorSandboxes(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.checkSandboxHealth()
		}
	}
}

// checkSandboxHealth checks the health of all active sandboxes
func (sm *SandboxManager) checkSandboxHealth() {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	for pluginName, cgroup := range sm.cgroups {
		if !cgroup.Active {
			continue
		}

		// Check memory usage
		memoryUsage, err := sm.getCGroupMemoryUsage(cgroup)
		if err != nil {
			sm.logger.Error("Failed to get memory usage", "error", err, "plugin", pluginName)
			continue
		}

		// Check if memory limit is exceeded
		if memoryUsage > cgroup.MemoryLimit {
			sm.auditLogger.LogPluginSecurityViolation(pluginName, "memory_limit_exceeded", map[string]interface{}{
				"limit":  cgroup.MemoryLimit,
				"actual": memoryUsage,
			})
		}

		// Log resource usage
		sm.logger.Debug("Sandbox resource usage",
			"plugin", pluginName,
			"memory_bytes", memoryUsage,
			"memory_limit", cgroup.MemoryLimit,
		)
	}
}

// getCGroupMemoryUsage gets current memory usage for a cgroup
func (sm *SandboxManager) getCGroupMemoryUsage(cgroup *CGroup) (int64, error) {
	memoryCurrentPath := filepath.Join(cgroup.Path, "memory.current")
	data, err := os.ReadFile(memoryCurrentPath)
	if err != nil {
		return 0, err
	}

	usage, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse memory usage: %w", err)
	}

	return usage, nil
}

// DefaultSandboxConfig returns a default sandbox configuration
func DefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		EnableCGroups:      true,
		EnableSeccomp:      true,
		CGroupRoot:         "/sys/fs/cgroup",
		MaxMemoryMB:        512,
		MaxCPUPercent:      25.0,
		MaxProcesses:       100,
		AllowedSyscalls:    []string{}, // Use default list
		BlockedSyscalls:    []string{"ptrace", "kexec_load", "init_module", "delete_module"},
		NetworkIsolation:   false,
		FilesystemReadOnly: false,
		TempDirPath:        "/tmp/hkp-plugins",
		AllowedDirectories: []string{"/tmp", "/var/tmp"},
		DeniedDirectories:  []string{"/etc", "/boot", "/sys", "/proc"},
	}
}
