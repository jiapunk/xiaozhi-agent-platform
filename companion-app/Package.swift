// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "XiaozhiProductCompanion",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ProductOnboardingCore",
            targets: ["ProductOnboardingCore"]
        ),
        .library(
            name: "ProductOnboardingESPProvision",
            targets: ["ProductOnboardingESPProvision"]
        ),
        .library(
            name: "ProductActionConsentUI",
            targets: ["ProductActionConsentUI"]
        ),
        .executable(
            name: "product-onboarding-core-tests",
            targets: ["ProductOnboardingCoreTests"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/espressif/esp-idf-provisioning-ios.git",
            exact: "3.1.0"
        ),
    ],
    targets: [
        .target(
            name: "ProductOnboardingCore",
            resources: [.process("PrivacyInfo.xcprivacy")]
        ),
        .target(
            name: "ProductOnboardingESPProvision",
            dependencies: [
                "ProductOnboardingCore",
                .product(
                    name: "ESPProvision",
                    package: "esp-idf-provisioning-ios",
                    condition: .when(platforms: [.iOS])
                ),
            ]
        ),
        .target(
            name: "ProductActionConsentUI",
            dependencies: ["ProductOnboardingCore"]
        ),
        .executableTarget(
            name: "ProductOnboardingCoreTests",
            dependencies: ["ProductOnboardingCore"],
            path: "Tests/ProductOnboardingCoreTests"
        ),
    ]
)
