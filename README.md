# Problem Statement 3 – Go Concurrency Explanation

## Overview

This repository contains the solution and explanation for **Problem Statement 3** from the Accuknox eBPF assignment. The task was to **analyze a Go snippet** that demonstrates concurrency with **goroutines** and **channels**.

---

## Code Snippet

```go
package main

import "fmt"

func main() {
    cnp := make(chan func(), 10)

    for i := 0; i < 4; i++ {
        go func() {
            for f := range cnp {
                f()
            }
        }()
    }

    cnp <- func() {
        fmt.Println("HERE1")
    }

    fmt.Println("Hello")
}
```

## Explanation

Channel Creation:

cnp := make(chan func(), 10) creates a buffered channel that can hold up to 10 functions.

Think of it as a mailbox where jobs (functions) are sent for workers to execute.

Worker Goroutines:

The loop for i := 0; i < 4; i++ launches 4 goroutines.

Each worker continuously reads from the channel and executes any function received, forming a simple worker pool.

Sending a Job:

cnp <- func() { fmt.Println("HERE1") } sends a function to the channel.

If executed, it would print "HERE1".

Main Goroutine Output:

fmt.Println("Hello") prints "Hello" immediately.

The program exits right after, so the worker goroutines never get to execute the job.

Why "HERE1" is Not Printed:

In Go, when the main function ends, all other goroutines are terminated.

The workers don’t get a chance to pick up the job before the program exits.
