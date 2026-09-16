import ProductOnboardingCore

enum WiFiCredentialsTests {
    static func run() throws {
        try validBoundariesAndOneUse()
        try rejectsInvalidSSIDAndPassphrase()
    }

    private static func validBoundariesAndOneUse() throws {
        let credentials = try WiFiCredentialTicket(
            ssid: String(repeating: "s", count: 32),
            passphrase: String(repeating: "p", count: 63)
        )
        let value = try credentials.consume()
        try check(value.ssid.utf8.count == 32)
        try check(value.passphrase.utf8.count == 63)
        try expectThrows(OnboardingContractError.alreadyConsumed) {
            try credentials.consume()
        }
    }

    private static func rejectsInvalidSSIDAndPassphrase() throws {
        let invalid: [(String, String)] = [
            ("", "12345678"),
            (String(repeating: "s", count: 33), "12345678"),
            ("bad\nssid", "12345678"),
            ("valid", "1234567"),
            ("valid", String(repeating: "p", count: 64)),
            ("valid", "bad\npass"),
        ]
        for (ssid, passphrase) in invalid {
            try expectThrows(OnboardingContractError.invalidFields) {
                try WiFiCredentialTicket(ssid: ssid, passphrase: passphrase)
            }
        }
    }
}
