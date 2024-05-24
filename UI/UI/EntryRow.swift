import SwiftUI

struct EntryRow: View {
    let domain: String
    let description: String
    let userId: String

    var body: some View {
        VStack(alignment: .leading) {
            Text(domain)
                .font(.headline)
            Text(description)
                .font(.subheadline)
            Text(userId)
                .font(.footnote)
        }
        .padding()
    }
}

struct EntryRow_Previews: PreviewProvider {
    static var previews: some View {
        EntryRow(domain: "example.com", description: "Sample Description", userId: "user@example.com")
    }
}
