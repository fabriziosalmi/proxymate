//
//  AhoCorasick.swift
//  proxymate
//
//  Aho-Corasick multi-pattern string matching automaton.
//  Compiles N patterns into a trie with failure links, then scans
//  input text in O(text_length + matches) regardless of pattern count.
//  Used by RuleEngine for content rules instead of linear scan.
//

import Foundation

nonisolated final class AhoCorasick: @unchecked Sendable {

    private struct Node {
        var children: [UInt8: Int] = [:]  // byte → node index
        var fail: Int = 0                  // failure link
        var outputs: [(name: String, pattern: String)] = []
    }

    private var nodes: [Node] = [Node()]  // index 0 = root
    private var compiled = false
    var isEmpty: Bool { patternCount == 0 }

    // MARK: - Build

    /// Add a pattern to the automaton. Must be called before compile().
    func addPattern(name: String, pattern: String) {
        let bytes = Array(pattern.lowercased().utf8)
        var current = 0
        for byte in bytes {
            if let next = nodes[current].children[byte] {
                current = next
            } else {
                let newIdx = nodes.count
                nodes.append(Node())
                nodes[current].children[byte] = newIdx
                current = newIdx
            }
        }
        nodes[current].outputs.append((name, pattern))
    }

    /// Build failure links. Must be called after all patterns are added.
    func compile() {
        var queue: [Int] = []

        // Initialize failure links for depth-1 nodes
        for (_, childIdx) in nodes[0].children {
            nodes[childIdx].fail = 0
            queue.append(childIdx)
        }

        // BFS to build failure links
        while !queue.isEmpty {
            let current = queue.removeFirst()
            for (byte, childIdx) in nodes[current].children {
                queue.append(childIdx)

                var fail = nodes[current].fail
                while fail != 0 && nodes[fail].children[byte] == nil {
                    fail = nodes[fail].fail
                }
                nodes[childIdx].fail = nodes[fail].children[byte] ?? 0
                if nodes[childIdx].fail == childIdx {
                    nodes[childIdx].fail = 0  // avoid self-loop
                }

                // Merge outputs from failure chain
                nodes[childIdx].outputs.append(contentsOf: nodes[nodes[childIdx].fail].outputs)
            }
        }
        compiled = true
    }

    // MARK: - Search

    struct Match: Sendable {
        let name: String
        let pattern: String
        let position: Int
    }

    /// Search text for any pattern match. Returns first match or nil.
    /// O(text.count) regardless of pattern count.
    func search(_ text: String) -> Match? {
        guard compiled else { return nil }
        let bytes = Array(text.lowercased().utf8)
        var current = 0

        for (i, byte) in bytes.enumerated() {
            while current != 0 && nodes[current].children[byte] == nil {
                current = nodes[current].fail
            }
            current = nodes[current].children[byte] ?? 0

            if !nodes[current].outputs.isEmpty {
                let out = nodes[current].outputs[0]
                return Match(name: out.name, pattern: out.pattern, position: i)
            }
        }
        return nil
    }

    /// Check if any pattern matches (no allocation on miss).
    func containsMatch(_ text: String) -> Bool {
        search(text) != nil
    }

    var patternCount: Int {
        nodes.reduce(0) { $0 + $1.outputs.count }
    }
}
