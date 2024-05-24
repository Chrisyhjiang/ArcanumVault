import SwiftUI

struct AuthenticationView: View {
    @State private var masterPassword = ""
    @State private var selectedAuthMethod: String = "password"
    @State private var authenticationFailed = false
    @State private var isUnlocked = false
    @State private var vaultOutput = ""
    @State private var showMasterPasswordPrompt = false

    var body: some View {
        VStack {
            if isUnlocked {
                PasswordListView()  // Your view after authentication
            } else {
                VStack {
                    Image(systemName: "lock.fill")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 100, height: 100)
                        .padding()
                    
                    Text("Passwords Are Locked")
                        .font(.title)
                        .padding()
                    
                    Text(vaultOutput.isEmpty ? "Touch ID or enter the password to unlock." : vaultOutput)
                        .multilineTextAlignment(.center)
                        .padding()

                    if selectedAuthMethod == "password" {
                        SecureField("Enter password", text: $masterPassword)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .padding()
                    }

                    HStack {
                        Button(action: { selectedAuthMethod = "password" }) {
                            Text("Password")
                                .padding()
                                .background(selectedAuthMethod == "password" ? Color.blue : Color.gray)
                                .foregroundColor(.white)
                                .cornerRadius(8)
                        }

                        Button(action: { selectedAuthMethod = "fingerprint" }) {
                            Text("Fingerprint")
                                .padding()
                                .background(selectedAuthMethod == "fingerprint" ? Color.blue : Color.gray)
                                .foregroundColor(.white)
                                .cornerRadius(8)
                        }
                    }
                    .padding()

                    Button(action: authenticate) {
                        Text("Unlock")
                            .padding()
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                    }

                    if authenticationFailed {
                        Text("Authentication Failed")
                            .foregroundColor(.red)
                            .padding()
                    }
                }
                .padding()
            }
        }
        .onAppear(perform: onLoad)
        .alert(isPresented: $showMasterPasswordPrompt) {
            Alert(
                title: Text("Set Master Password"),
                message: Text("Master password is not set. Please set it to proceed."),
                primaryButton: .default(Text("Set"), action: {
                    setMasterPassword()
                }),
                secondaryButton: .cancel()
            )
        }
    }

    func onLoad() {
        installCLIIfNeeded {
            checkMasterPassword()
        }
    }

    func installCLIIfNeeded(completion: @escaping () -> Void) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/pip3") // Use the full path to pip
        process.arguments = ["install", "."]

        // Get the current directory of the file
        let currentDirectory = FileManager.default.currentDirectoryPath

        // Navigate two directories up
        let projectDirectory = URL(fileURLWithPath: currentDirectory).appendingPathComponent("../../").standardized

        process.currentDirectoryURL = projectDirectory

        process.terminationHandler = { _ in
            DispatchQueue.main.async {
                completion()
            }
        }

        do {
            try process.run()
        } catch {
            print("Failed to install CLI: \(error.localizedDescription)")
        }
    }

    func checkMasterPassword() {
        let vaultPath = "/Library/Frameworks/Python.framework/Versions/3.10/bin/vault"
        print("Running vault check-master-password command on load")
        runCommand(vaultPath, arguments: ["check-master-password"]) { result in
            DispatchQueue.main.async {
                print("Vault command output: \(result)")
                self.vaultOutput = result
                if result.contains("Master password is not set") {
                    self.showMasterPasswordPrompt = true
                } else if result.contains("Master password is set") {
                    self.authenticate()
                }
            }
        }
    }

    func authenticate() {
        let vaultPath = "/Library/Frameworks/Python.framework/Versions/3.10/bin/vault"
        print("Selected authentication method: \(selectedAuthMethod)")
        if selectedAuthMethod == "password" {
            print("Authenticating with password")
            runCommand(vaultPath, arguments: ["authenticate", "--auth-method", "password", "--master-password", masterPassword]) { result in
                DispatchQueue.main.async {
                    print("Authentication output: \(result)")
                    if result.contains("Authentication succeeded") {
                        self.isUnlocked = true
                    } else {
                        self.authenticationFailed = true
                    }
                }
            }
        } else if selectedAuthMethod == "fingerprint" {
            print("Authenticating with fingerprint")
            runCommand(vaultPath, arguments: ["authenticate", "--auth-method", "fingerprint"]) { result in
                DispatchQueue.main.async {
                    print("Authentication output: \(result)")
                    if result.contains("Authentication succeeded") {
                        self.isUnlocked = true
                    } else {
                        self.authenticationFailed = true
                    }
                }
            }
        }
    }

    func setMasterPassword() {
        let vaultPath = "/Library/Frameworks/Python.framework/Versions/3.10/bin/vault"
        runCommand(vaultPath, arguments: ["set-master-password"], input: masterPassword) { result in
            DispatchQueue.main.async {
                print("Set master password output: \(result)")
                if result.contains("Master password set successfully") {
                    self.vaultOutput = "Master password set successfully. Please authenticate."
                } else {
                    self.vaultOutput = "Failed to set master password."
                }
            }
        }
    }

    func runCommand(_ launchPath: String, arguments: [String], input: String? = nil, completion: @escaping (String) -> Void) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        if let input = input {
            let inputPipe = Pipe()
            inputPipe.fileHandleForWriting.write(input.data(using: .utf8)!)
            process.standardInput = inputPipe
        }

        process.terminationHandler = { _ in
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            print("Command output: \(output)")
            completion(output)
        }

        do {
            try process.run()
        } catch {
            let errorMessage = "Failed to run process: \(error.localizedDescription)"
            print(errorMessage)
            completion(errorMessage)
        }
    }
}

struct AuthenticationView_Previews: PreviewProvider {
    static var previews: some View {
        AuthenticationView()
    }
}
