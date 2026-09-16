import Darwin
import Foundation

private struct TestFailure: Error, CustomStringConvertible {
    let description: String
}

func check(
    _ condition: @autoclosure () throws -> Bool,
    _ message: String = "expectation failed",
    file: StaticString = #fileID,
    line: UInt = #line
) throws {
    guard try condition() else {
        throw TestFailure(description: "\(file):\(line): \(message)")
    }
}

func expectThrows<E: Error & Equatable, T>(
    _ expected: E,
    _ operation: () throws -> T,
    file: StaticString = #fileID,
    line: UInt = #line
) throws {
    do {
        _ = try operation()
        throw TestFailure(description: "\(file):\(line): expected \(expected)")
    } catch let actual as E {
        try check(actual == expected, "expected \(expected), got \(actual)", file: file, line: line)
    } catch {
        throw TestFailure(description: "\(file):\(line): unexpected error \(error)")
    }
}

func expectAnyThrow<T>(
    _ operation: () throws -> T,
    file: StaticString = #fileID,
    line: UInt = #line
) throws {
    do {
        _ = try operation()
        throw TestFailure(description: "\(file):\(line): expected an error")
    } catch is TestFailure {
        throw TestFailure(description: "\(file):\(line): expected an error")
    } catch {
        return
    }
}

@MainActor
func expectAsyncThrows<E: Error & Equatable, T>(
    _ expected: E,
    _ operation: () async throws -> T,
    file: StaticString = #fileID,
    line: UInt = #line
) async {
    do {
        _ = try await operation()
        FileHandle.standardError.write(
            Data("\(file):\(line): expected \(expected)\n".utf8)
        )
        exit(1)
    } catch let actual as E {
        if actual != expected {
            FileHandle.standardError.write(
                Data("\(file):\(line): expected \(expected), got \(actual)\n".utf8)
            )
            exit(1)
        }
    } catch {
        FileHandle.standardError.write(
            Data("\(file):\(line): unexpected error \(error)\n".utf8)
        )
        exit(1)
    }
}

@main
enum ProductOnboardingCoreTestHarness {
    static func main() async {
        do {
            try await OnboardingQRCodeTests.run()
            try await DeviceClaimTests.run()
            try await AgentActionConsentTests.run()
            try await AgentActionConsentAccessAPITests.run()
            try await AgentActionConsentSessionTests.run()
            try await PushInstallationAPITests.run()
            try WiFiCredentialsTests.run()
            try OnboardingFlowTests().run()
            print("Product onboarding core: 38 scenarios passed")
        } catch {
            FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
            exit(1)
        }
    }
}
