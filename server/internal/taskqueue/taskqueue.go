// Package taskqueue implements a thread-safe, per-session task queue.
//
// The operator console enqueues tasks via gRPC; the session goroutine
// dequeues them on the next agent beacon and encodes them as TLV TASK
// messages for delivery.
//
// ACADEMIC/EDUCATIONAL USE ONLY.
package taskqueue

import (
	"sync"

	"github.com/google/uuid"
)

// ──────────────────────────────────────────────
//  Task types
// ──────────────────────────────────────────────

// TaskType identifies the kind of task to dispatch to an agent.
type TaskType uint16

const (
	TaskExec     TaskType = 0x01 // Execute a shell command
	TaskUpload   TaskType = 0x02 // Upload a file to the agent
	TaskDownload TaskType = 0x03 // Download a file from the agent
	TaskSysinfo  TaskType = 0x04 // Collect system information
	TaskSleep    TaskType = 0x05 // Change beacon interval
	TaskExit     TaskType = 0x06 // Terminate the agent
)

// String returns a human-readable name for the task type.
func (tt TaskType) String() string {
	switch tt {
	case TaskExec:
		return "EXEC"
	case TaskUpload:
		return "UPLOAD"
	case TaskDownload:
		return "DOWNLOAD"
	case TaskSysinfo:
		return "SYSINFO"
	case TaskSleep:
		return "SLEEP"
	case TaskExit:
		return "EXIT"
	default:
		return "UNKNOWN"
	}
}

// ──────────────────────────────────────────────
//  Task
// ──────────────────────────────────────────────

// Task represents a single queued task for an agent.
type Task struct {
	ID       string   // Server-assigned unique identifier (UUID)
	Type     TaskType // What the agent should do
	Data     []byte   // Task-specific payload (command string, file bytes, etc.)
	Operator string   // Identity of the operator who queued this task
}

// ──────────────────────────────────────────────
//  Queue
// ──────────────────────────────────────────────

// Queue is a thread-safe FIFO queue of tasks for a single session.
type Queue struct {
	mu    sync.Mutex
	tasks []Task
}

// New creates a new empty task queue.
func New() *Queue {
	return &Queue{}
}

// Enqueue adds a task to the back of the queue and returns the
// server-assigned task ID.
func (q *Queue) Enqueue(taskType TaskType, data []byte, operator string) string {
	id := uuid.New().String()

	q.mu.Lock()
	defer q.mu.Unlock()

	q.tasks = append(q.tasks, Task{
		ID:       id,
		Type:     taskType,
		Data:     data,
		Operator: operator,
	})

	return id
}

// Dequeue removes and returns the next task from the front of the queue.
// Returns nil if the queue is empty.
func (q *Queue) Dequeue() *Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.tasks) == 0 {
		return nil
	}

	task := q.tasks[0]
	q.tasks = q.tasks[1:]
	return &task
}

// DequeueAll removes and returns all pending tasks.
// Returns nil if the queue is empty.
func (q *Queue) DequeueAll() []Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.tasks) == 0 {
		return nil
	}

	tasks := q.tasks
	q.tasks = nil
	return tasks
}

// Len returns the number of pending tasks.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tasks)
}

// Peek returns the next task without removing it.
// Returns nil if the queue is empty.
func (q *Queue) Peek() *Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.tasks) == 0 {
		return nil
	}

	task := q.tasks[0]
	return &task
}
