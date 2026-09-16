import Foundation
import ProductOnboardingCore

enum OnboardingQRCodeTests {
    private static let canonical =
        #"{"name":"XA-12ABEF","password":"ABCDEFGHJKLMNPQRSTUV","pop":"ABCDEFGHJKLMNPQRSTUVWXYZ23","security":2,"transport":"softap","username":"xiaozhi","ver":"v1"}"#

    static func run() async throws {
        try canonicalFactoryPayloadIsAcceptedOnce()
        try rejectsNonCanonicalAndExpandedDocuments()
        try await concurrentConsumeHasExactlyOneWinner()
    }

    private static func canonicalFactoryPayloadIsAcceptedOnce() throws {
        let ticket = try OnboardingQRCode.parse(canonical)
        try check(ticket.device == OnboardingDevice(name: "XA-12ABEF"))

        let identity = try ticket.consume()
        try check(identity.device.name == "XA-12ABEF")
        try check(identity.username == "xiaozhi")
        try check(identity.proofOfPossession == "ABCDEFGHJKLMNPQRSTUVWXYZ23")
        try check(identity.softAPPassword == "ABCDEFGHJKLMNPQRSTUV")
        try expectThrows(OnboardingContractError.alreadyConsumed) {
            try ticket.consume()
        }
    }

    private static func rejectsNonCanonicalAndExpandedDocuments() throws {
        let variants = [
            " " + canonical,
            canonical.replacingOccurrences(of: #""ver":"v1""#, with: #""ver":"v1","extra":"x""#),
            canonical.replacingOccurrences(of: #""ver":"v1""#, with: #""ver":"v1","ver":"v1""#),
            canonical.replacingOccurrences(of: #""security":2"#, with: #""security":1"#),
            canonical.replacingOccurrences(of: #""security":2"#, with: #""security":true"#),
            canonical.replacingOccurrences(of: #""transport":"softap""#, with: #""transport":"ble""#),
            canonical.replacingOccurrences(of: #""username":"xiaozhi""#, with: #""username":"other""#),
            canonical.replacingOccurrences(of: "XA-12ABEF", with: "XA-12abef"),
            canonical.replacingOccurrences(of: "ABCDEFGHJKLMNPQRSTUV", with: "ABCDEFGH1KLMNPQRSTUV"),
        ]
        for payload in variants {
            try expectAnyThrow {
                try OnboardingQRCode.parse(payload)
            }
        }
    }

    private static func concurrentConsumeHasExactlyOneWinner() async throws {
        let ticket = try OnboardingQRCode.parse(canonical)
        let results = await withTaskGroup(of: Bool.self, returning: [Bool].self) {
            group in
            for _ in 0..<64 {
                group.addTask {
                    do {
                        _ = try ticket.consume()
                        return true
                    } catch {
                        return false
                    }
                }
            }
            var collected: [Bool] = []
            for await result in group {
                collected.append(result)
            }
            return collected
        }
        try check(results.filter { $0 }.count == 1)
        try check(results.filter { !$0 }.count == 63)
    }
}
