import Foundation

/// Fixed-size FIFO sample buffer — oldest sample evicted on overflow. Backs the
/// short-term histories (system CPU, latency) that power the sustained-spike
/// rule. In-memory only; never written to disk.
struct RingBuffer<Element> {
    let capacity: Int
    private var storage: [Element] = []
    private var head = 0  // index of the oldest element once the buffer is full

    init(capacity: Int) {
        precondition(capacity > 0)
        self.capacity = capacity
        storage.reserveCapacity(capacity)
    }

    var count: Int { storage.count }
    var isFull: Bool { storage.count == capacity }

    mutating func append(_ element: Element) {
        if storage.count < capacity {
            storage.append(element)
        } else {
            storage[head] = element
            head = (head + 1) % capacity
        }
    }

    /// Contents ordered oldest → newest.
    var elements: [Element] {
        Array(storage[head...]) + Array(storage[..<head])
    }
}

extension RingBuffer: Sendable where Element: Sendable {}
