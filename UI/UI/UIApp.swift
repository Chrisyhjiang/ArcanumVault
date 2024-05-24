import SwiftUI

@main
struct UIApp: App { // Ensure the struct name matches your app name
    var body: some Scene {
        WindowGroup {
            AuthenticationView() // Set AuthenticationView as the initial view
        }
    }
}
