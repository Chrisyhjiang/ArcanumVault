import Foundation

struct PasswordEntry: Identifiable {
    var id = UUID()
    let domain: String
    let description: String
    let userId: String
    let vaultID: String
}
