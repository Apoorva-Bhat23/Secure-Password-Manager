# Secure-Password-Manager
### I. INTRODUCTION
In today’s digital age, every user manages multiple online accounts on various platforms, each of which requires a unique, complex password to ensure security. Remembering these unique credentials for every account can  be challenging, often leading to the risky practice of using the same password across multiple platforms. Password managers offer a practical solution, providing a secure vault to store and manage multiple passwords  hile generating unique, strong credentials for each account. However, while many popular password managers exist, they often rely on cloud-based storage solutions, which can pose additional risks if users’ sensitive  information is not adequately secured. This project addresses these risks by offering a locally hosted, secure password manager that leverages robust encryption methods to protect user credentials and improve ease of  access through an autofill feature. This password manager is designed with a focus on security and user convenience, employing cryptographic methods such as Argon2 hashing and Fernet encryption to safeguard stored data. A master password is required for access, and only authorized users with this password can retrieve and decrypt stored credentials. The manager also provides a session timeout feature to protect sensitive information  from unauthorized access during periods of inactivity, along with clipboard management to prevent data leakage after password autofill. Through these features, this project aims to deliver a practical, secure solution for managing passwords while enhancing the user experience by automatically populating login fields in web applications. 

## II. REQUIREMENTS FOR THE PASSWORD MANAGER SYSTEM
### A. Project Goals
To create an effective and secure password manager, the following goals are essential:
• Develop a Secure Password Manager: Employ robust encryption techniques to ensure that all stored credentials remain confidential and protected against unauthorized access.
• Implement Autofill Functionality: Provide an autofill feature to streamline the login process, enhancing usability by allowing users to securely populate login fields automatically.
• Integrate Security Features: Include additional protections like session timeouts to automatically secure the application after periods of inactivity, and clipboard management to prevent data leaks after password  copying.

### B. Technologies Used
Several specialized libraries and frameworks are utilized to build and secure the password manager:
• Flask: A lightweight backend framework used to handle HTTP requests, render the autofill interface, and manage user interactions within the web application.
• Cryptography Library (Fernet Encryption): Provides secure encryption of user passwords, ensuring that credentials are only accessible to authorized users with the correct master password.
• Argon2 Hashing: This password hashing algorithm secures the master password, making it highly resistant to brute-force and dictionary attacks.
• Secure Clipboard Management (Pyperclip): Manages temporary storage of sensitive information in the clipboard, automatically clearing copied passwords after a set time to prevent unauthorized access.

## III. LITERATURE SURVEY
As the need for secure and efficient password management grows, a variety of tools have emerged to meet this demand. Popular password managers, such as Google Password Manager, LastPass, and Dashlane, offer essential features like secure storage, password generation, encryption, and crossplatform synchronization. These tools help users manage complex passwords across various accounts, improving security while reducing the burden of remembering numerous credentials. However, existing tools often face limitations. Many rely on cloud-based storage, which, although convenient, can expose user data to risks associated with server breaches. Additionally, most solutions rely on a single layer of protection, such as a master password, which can leave sensitive information vulnerable if compromised. Further, features such as clipboard management and session  timeout—important for preventing accidental disclosure of sensitive data—are either lacking or insufficient in many current tools.

## A. Existing Password Managers
Current password management solutions, like Google Password Manager and LastPass, offer secure password storage, encryption, and autofill capabilities, making them popular among users. However, the reliance on cloud-based storage often limits user control over data location and access. While encryption protects data, a lack of comprehensive session management and clipboard control can increase the risk of data exposure.

## B. Gap Analysis
While existing solutions provide basic password management functions, there are critical gaps in data security and user control. Many tools lack options for local data storage, which is essential for users who prefer 
offline data storage to prevent exposure to server-based risks. Additionally, features such as clipboard management and session timeout, which help prevent accidental exposure, are often absent. This project seeks to address these limitations by implementing a locally stored password manager with encrypted data storage, session timeout, and clipboard management for enhanced security and user control.

### IV. SYSTEM DESIGN
## A. System Overview
The password manager is designed to securely store and
manage user credentials while offering an autofill feature
that streamlines the login process. The primary functions of
the system include credential encryption, secure storage, user
authentication, and clipboard management to protect sensitive
information. This system operates locally, ensuring data is
stored securely without reliance on external servers, thereby
reducing risks associated with cloud storage breaches. The
primary components of the system are the Flask-based backend, a cryptographically secure database file, and a web-based
user interface. The Flask server facilitates communication
between the user interface and the encrypted local storage,
while cryptographic libraries manage encryption and hashing
processes to ensure data confidentiality and integrity.

## B. Architecture Diagram
Fig. 1. Flowchart of Secure Password Manager This flowchart illustrates the main functionalities of the Secure Password Manager, a system designed to securely store, retrieve, and manage user credentials in an encrypted
database. Each function in this flowchart interacts with the encrypted database file, using Fernet encryption to secure all stored data. This ensures that sensitive information, including passwords and login credentials, remains protected from unauthorized access. The flowchart provides a clear, step-by-step visualization of how the password manager operates, guiding the user through various  functionalities while maintaining a high level of security.

## C. Component Descriptions
1) User Interface (UI):
• Functionality: Allows users to input credentials, view
saved profiles, and autofill login fields.
• Technologies Used: HTML, CSS, JavaScript for webbased interaction.
• Interfaces: Communicates with the Flask backend to send
and receive encrypted credentials.
2) Backend (Flask Server):
• Functionality: Manages user requests, processes credentials, handles encryption/decryption, and manages session
timeouts.
• Technologies Used: Python with Flask framework.
• Key Algorithms: Implements session management for
timeouts, clipboard clearing, and input handling with
timeout-based prompts.
3) Data Storage:
• Functionality: Encrypted storage of credentials in a local
database file.
• Technologies Used: Fernet encryption (from the cryptography library) for encrypting and decrypting user
credentials.
• Data Structures: JSON format for storing credentials
as key-value pairs (domain, username, password) in an
encrypted file.
4) Data Design:
The database file is a flat-file storage that keeps user
credentials in encrypted form. Each entry is structured as a
JSON object containing:
• Domain: Website or app name for which the credentials
are stored.
• Username: User’s login name.
• Password: Encrypted password.
Data is accessed and modified via functions within the backend, and encryption ensures data remains secure even if the
database file is accessed externally. Clipboard data is managed
temporarily and cleared post-use to prevent data leakage.
5) User Interface Design:
The UI is designed to be straightforward and user-friendly,
ensuring smooth navigation for password management tasks:
• Screen Layouts: Includes a main login page, a password
vault screen, and an autofill form.
• Navigation Flow: Users log in with a master password
to access stored credentials and can navigate between
adding, retrieving, and autofilling passwords.
• User Interaction Patterns: Interaction is kept minimal,
with simple input forms for entering and viewing data.
6) Technical Considerations:
• Programming Language: Python, for its extensive library
support and compatibility with cryptographic functions.
• Framework: Flask is chosen for its lightweight and
efficient request-handling capability, suitable for local
applications.
• Security Libraries: cryptography library for robust encryption and Argon2 hashing for secure password protection.
• Clipboard Management: Pyperclip for managing clipboard data and automatically clearing it after a set time.
7) Security Design:
Security is a core aspect of this project, and several measures have been implemented to ensure data protection:
• Authentication: Users access the system via a master
password, hashed using Argon2 to resist brute-force attacks.
• Authorization: Only authorized users (those with the
correct master password) can view or modify saved
credentials.
• Encryption: Credentials are encrypted with Fernet encryption before storage, ensuring they remain inaccessible
without the encryption key.
• Session Timeout: Implements automatic session timeout
after a period of inactivity to prevent unauthorized access.
• Clipboard Management: Automatically clears sensitive
data from the clipboard after a set time to prevent
accidental data exposure.
8) Performance Optimization:
• Caching: Frequently accessed data, like user credentials,
is cached within the session to reduce data retrieval time.
• Clipboard Timeout: Minimizes the risk of sensitive data
exposure by clearing clipboard data within 30 seconds of
copying.
• Efficient Encryption: Optimized Argon2 and Fernet configurations for both security and performance, balancing
encryption speed with security strength.
9) Error Handling and Exception Management:
The system implements error handling to ensure smooth
operation and user-friendly feedback:
• Error Logging: Logs errors for debugging, especially
during encryption/decryption and file access processes.
• User-Friendly Messages: Displays clear, informative error
messages when credentials cannot be found or a wrong
password is entered.
• Recovery Mechanisms: Provides options to retry login or
re-enter credentials in case of input errors or timeouts.
V. IMPLEMENTATION DETAILS
A. Master Password Verification
The application begins with a login step, where the user
enters their master password. This password is crucial as it
grants access to the password manager’s database and decrypts
stored credentials. During login, the entered password is
verified against a securely stored hash to ensure authentication.
If the password is correct, the system grants access; otherwise,
the user is prompted to re-enter their credentials. This step
protects the encrypted data from unauthorized access.
B. Encryption and Decryption
The password manager utilizes Fernet encryption to secure
user credentials stored in the database file. When saving new or
modified data, the system encrypts it with a unique encryption
key generated from the master password. Decryption occurs
only after successful login, allowing the system to display or
use stored data. This process ensures that sensitive information
remains unreadable outside of the authorized session.
C. Add New Profile
Users can add a new profile by entering the necessary
information, such as username, password, and domain name.
Once entered, the data is immediately encrypted with Fernet
encryption before being saved to the database. This ensures
that the new profile data is protected from unauthorized
access. After encryption, the data is stored securely within
the database file. Each new profile that is created keeps user
information safe while being accessible upon demand.
D. Show All Profiles
This option allows users to retrieve all stored profiles from
the database. The encrypted data is decrypted in real time,
allowing users to view their saved credentials in a readable
format. This functionality gives users quick access to their
login information while ensuring data is displayed only within
the authenticated session. The data remains encrypted on disk,
safeguarding it outside the session. Users can review and verify
their stored information in a secure interface.
E. Edit Profile
This function allows users to modify or update existing profile details, such as updating a password. The selected profile
data is decrypted to allow for editing, and once modifications
are complete, the updated information is re-encrypted. The
application then saves the encrypted data back to the database,
ensuring continuous data security. This process guarantees that
updated information is securely stored and managed.
F. Delete Profile
Users can delete an unwanted profile from the password
manager, removing it entirely from the database. Once the
profile is selected, the system removes the corresponding
encrypted data from the database file. This functionality helps
users maintain an organized and clean database, reducing
unnecessary data storage. The deletion is final, ensuring that
sensitive information is completely removed from the system.
It ensures that users retain full control over their stored
credentials.
G. Random Password Generation
To assist users in creating strong passwords, the application
includes a random password generator. This feature generates
a secure, random password that users can utilize for new
accounts or update existing ones. The generated password
follows best practices for security, including a mix of uppercase, lowercase, numbers, and special characters. Users can
directly save the generated password into a profile, where it
will be encrypted. This functionality enhances account security
by promoting strong password practices.
H. Change Master Password
Users have the option to update their master password
to enhance security over time. When changing the master
password, the application re-encrypts all stored data with the
new password to maintain encryption integrity. The updated
master password is securely hashed and stored for future
verifications. This feature provides flexibility and reinforces
data protection as the master password is the key to all
encrypted information. It ensures that only the new password
can access the stored credentials.
I. Session Timeout and Clipboard Management
To enhance security, the application includes a session
timeout feature that logs the user out after a period of 90
seconds of inactivity. Clipboard management clears sensitive
data, such as copied passwords, after use to prevent accidental
exposure. The session timeout protects the application from
unauthorized access if left unattended, and clipboard clearing
prevents unauthorized access to copied passwords. Both features contribute to a more secure, controlled user experience,
protecting user data beyond active use.
J. Autofill Functionality
The autofill functionality retrieves encrypted credentials for
a specified profile and fills login fields automatically for the
user. Upon selection, the application decrypts the necessary
data and populates the relevant fields, such as username
and password. This feature simplifies login processes for
frequently accessed accounts without requiring manual entry.
After use, the decrypted data remains secure within the session, preventing accidental exposure. Autofill optimizes user
experience while preserving security standards.
VI. RESULTS
A. User Interface
The password manager has a straightforward and userfriendly interface with an accessible autofill form on a web
page.
B. Encryption and Security Verification
Strong security is ensured through password encryption and
master password verification, protecting user data.
C. Functionality Validation
Test cases confirm that the autofill feature accurately retrieves and inputs credentials based on specified input domains.
Fig. 2. Login Page Interface
Fig. 3. Auto-fill Functionality Interface
VII. CONCLUSION
A. Summary of Achievements
This project successfully aims to delivers a secure password
manager with encryption, master password verification, and an
auto-fill feature. Some of the Key security mechanisms, such
as clipboard clearing and session timeouts, enhance protection
for sensitive information. Successfully implemented a userfriendly interface, making it easy for users to manage their
credentials across multiple platforms. The system architecture
ensures minimal latency during auto-fill operations, resulting
in a smooth and responsive experience. Comprehensive test
cases validate functionality, demonstrating reliable retrieval of
credentials and strong encryption of stored data. The modular
design allows for easy updates and scalability, supporting
future enhancements without compromising security.
B. Future Work
Potential future enhancements include:
• Multi-Factor Authentication (MFA): Adding an extra
security layer.
• Database Scalability: Transitioning to an SQL database
to support larger datasets and search functionalities.
