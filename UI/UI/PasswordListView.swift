import SwiftUI

struct PasswordListView: View {
    @State private var searchText = ""
    @State private var passwords = [PasswordEntry]()
    @State private var output = ""

    var body: some View {
        VStack {
            HStack {
                SearchTextField(text: $searchText)
                Button(action: addPassword) {
                    Image(systemName: "plus.circle")
                }
                Button(action: moreOptions) {
                    Image(systemName: "ellipsis.circle")
                }
            }
            .padding()

            List(filteredPasswords, id: \.id) { password in
                HStack {
                    EntryRow(domain: password.domain, description: password.description, userId: password.userId)
                    Spacer()
                    Button(action: { updatePassword(entry: password) }) {
                        Image(systemName: "pencil")
                    }
                    Button(action: { deletePassword(entry: password) }) {
                        Image(systemName: "trash")
                    }
                }
            }

            Text(output)
                .padding()
                .foregroundColor(.red)

            Spacer()
        }
        .padding()
        .onAppear(perform: fetchPasswords)
    }

    var filteredPasswords: [PasswordEntry] {
        if searchText.isEmpty {
            return passwords
        } else {
            return passwords.filter { $0.domain.contains(searchText) || $0.description.contains(searchText) }
        }
    }

    func fetchPasswords() {
        let vaultPath = "/Library/Frameworks/Python.framework/Versions/3.10/bin/vault"
        runCLICommand(vaultPath, arguments: ["show"]) { result in
            DispatchQueue.main.async {
                self.output = result
                self.passwords = parsePasswords(output: result)
            }
        }
    }

    func parsePasswords(output: String) -> [PasswordEntry] {
        var entries = [PasswordEntry]()
        let lines = output.split(separator: "\n")

        for line in lines {
            let components = line.split(separator: ",")
            if components.count == 4 {
                let entry = PasswordEntry(domain: String(components[0]), description: String(components[1]), userId: String(components[2]), vaultID: String(components[3]))
                entries.append(entry)
            }
        }

        return entries
    }

    func addPassword() {
        // Show a dialog or another view to add a new password
        // After adding, call fetchPasswords() to refresh the list
    }

    func updatePassword(entry: PasswordEntry) {
        // Show a dialog or another view to update the password
        // After updating, call fetchPasswords() to refresh the list
    }

    func deletePassword(entry: PasswordEntry) {
        let vaultPath = "/Library/Frameworks/Python.framework/Versions/3.10/bin/vault"
        runCLICommand(vaultPath, arguments: ["remove", entry.vaultID]) { result in
            DispatchQueue.main.async {
                self.output = result
                fetchPasswords()
            }
        }
    }

    func moreOptions() {
        // Implement the logic for more options
    }

    func runCLICommand(_ launchPath: String, arguments: [String], input: String = "", completion: @escaping (String) -> Void) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        if !input.isEmpty {
            let inputPipe = Pipe()
            inputPipe.fileHandleForWriting.write(input.data(using: .utf8)!)
            inputPipe.fileHandleForWriting.closeFile()
            process.standardInput = inputPipe
        }

        process.terminationHandler = { _ in
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            completion(output)
        }

        do {
            try process.run()
        } catch {
            completion("Failed to run process: \(error.localizedDescription)")
        }
    }
}

struct PasswordListView_Previews: PreviewProvider {
    static var previews: some View {
        PasswordListView()
    }
}
