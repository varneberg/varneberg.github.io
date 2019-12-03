# INF226 QUIZ ANSWERS

1. What is the definition of software security?
   * When a program functions according to the intentions in an adverserial enviroment

2. What does software security logic consist of? And what are some examples of these?
   * Requirements
     * Capture the intentions of the software
     * Spelling out our intentions
     * Examples:
       * Availability of the service  
       * Capacity
       * Integrity of data
       * Authentication of data
       * Recoverability
   * Assumptions
     * Spelling out our knowlegde of the software until it runs
     * Examples:
       * Assumptions pointing towards problems:
         * User input cannot be trusted to have a property X
         * IP adresses can be spoofed
         * Computers has finite resources
         * Programmers write bugs
       * Assumptions pointing towards solutions:
         * Checking the input so we know it has a desired property
         * An attacker cant guess a random 128 bit number
         * Semantics of a program
         * Correct type checker
         * Robust internet routing
   * Mechanisms
     * Satisfying the requirements given the assumptions
     * Examples:
       * Choice of programming language
       * Rate limiting
       * Sanity checks on user inputs
       * Access control lists
       * Optimisation of algorithms
       * Encryption
  
3. What is a vulnerability?
   * A circumstance where the program fails to behave as intended. When the program fails to be secure.

4. What are the vulnerability disclosure and what stances are there?
   * Information given to the public about a security related problem
   * No disclosure
     * No details are given to the public
   * Coordinated disclosure
     * Some details are given to the public once fixes has been made to the software
   * Full disclosure
     * All details are given public

5. What is an exploit?
   * A procedure taking advantage of a vulnerability, demonstrating the vulnerability of the program

6. What is an RCE vulnerability?
   * Remote Code Execution. When an attacker gets permission to run code on a victims machine
  
7. How does the call stack work?
    * The stack stores return addresses for function call
    * On call the pointer is pushed on the stack
    * When function closes, the pointer is popped from the stack

8. How does an attacker use an shell-code exploit?
   * By filling the buffer with hes own code and overwriting the return pointer to point to hes own code. This can spawn a shell, giving the attacker RCE access to the machine
  
9. For what reasong could an attacker use NO-OP sled?
    * When the attacker does not know the adress of the buffer.

10. What is ROP?
    * Return oriented programming. When the attacker uses prexisting code in the program instad of uploading a shell

11. How can a programmer prevent a buffer overflow attack?
    * Write better C code(self explaining)
    * Static analysis
    * Stack canaries
      * Secret value placed on the stack every time the program is run
      * Checks if the number from pointer has been modified on function returning
      * Terminates if modification is detected
    * W^X
      * OS enforcing writeable memory cannot be executed
      * Prevents loading shell in writeable buffers
    * Address space layout randomisation
      * Randomising the layout when allocating memory in the system
      * Makes the attacker guess the locations of functions and libraries

12. What are some of the best practises to avoid buffer overflow?
    * Use memory safe languages
    * Memory safe abstractions in unsafe languages(e.g vectors and smart pointers in C++)
    * Use the compiler to find vulnerabilities
    * Run static analysis to identify bugs
  
13. What is memory safety?
    * Each part of the program is only given access to the memory locations they are permitted

14. What should and shouldn't a function access in a program?
    * A function should access:
      1. Arguments from the caller
      2. Global variables
      3. Local variables
    * A functions should not access variables from another function

15. How does one break memory-safety?
    * Using:
      * Pointer arithmetics 
      * Unconstrained casting
      * No bounds-check on array access
      * Unsafe pointer de-allocation

16. Name some memory safe and not memory safe languages
    * Safe:
      * Java, C#, most scripting languages
    * Unsafe:
      * Assembly
      * C
      * C++

17. How does theses languages achieve memory safety?
    * Garbage collection (Lisp, JAVA, Haskell,..)
    * Resource allocation in RAII and borrows checker (Rust)
  
18. What is undefines behaviour?
    * When code does not behave according to language standard

19. What are some problems with sql?
    * Confusing between data and queries
    * Strings are used to represent data and queries

20. How do you prevent SQLi attacks?
    * Prepared statments

21. What is STRIDE?
    * Used for developing threat models
    * Spoofing
    * Tampering
    * Repudiation
    * Information disclosure
    * Denial of service
    * Elevation of privilegde

22. What is DREAD?
    * Used for ranking threats
      * Damage potential
      * Reproducibility
      * Exploitation
      * Affected users
      * Discoverability

23. What is functional decomposistion?
    * An overview of the components in a system
    * A detailed map over comunication between components
    * Description of the function of each of the components

24. What is a threat model?
    * Applicates our assumptions about a system
    * What threats apllies to the system?
    * Trust between components?
    * Which threats apply where?

25. What is a trust boundary?
    * When data is comunicated between components, it crosses a trust boundry

26. How do you analize defence in depth?
    * Find out what components are affected
    * Are there any linchpins?
    * Detect failures
    * Migitate failures

27. What is trusting trust?
    * Trusting someone else on something because they claim it is to be trusted
    * At one point we have to start trusting the people making the software

28. Why is it important to trust a compiler and what can you do trust a compiler?
    * A compiler could recognize code and compile backdoors without the user knowing
    * To trust a compiler:
      * Read the source code
      * Trust the compiler who compiled the compiler

29. How do you test a compiler?
    * Get an independent compiler to compare with the test compiler
    * Compile the source code using both compilers and copile the executeables
    * Compare the results
    * The binaries for each of the executeables will be different, but if they are functionally equivavalent, one can trust the compiler

30. What is CVE?
    * Common Vulnerability Exposures
    * A CVE is an entry stored in the CVE database consiting of a:
      * unique number
      * description
      * at least one public reference

31. What is CNA's?
    * CVE numbering authorities
    * Assigns numbers to CVE's

32. What is CVSS?
    * Common Vulnerability Scoring System
    * Scores CVS from 1 - 10

33. What are the metrics in CVSS?
    1. Base metrics
       * Access vectors
         * Local, network or adjacent network
    2. Impact metrics
       * Rates impact on a scale from None/Partial/Complete based on:
         * Confidentiality
         * Integrity
         * Availability
    3. Temporal metrics
        * Metrics who changes overtime
        * Rated from:
          * Exploitability(Unproven, Proof-of-concept, Functional, High)
  
34. What is CWE?
    * Common Weakness Enumeration
    * List of common weaknesses present in software 
    * More fine grained than OWASP's Top 10, but similar
    * Structure:
      * Architecture components
      * Development concepts
      * Research concepts

35. What is NVD?
    * National Vulnerability Database
    * Contains analysis of known vulnerabilities 
      * CVE number
      * CWE numbers
      * CVSS
      * Versions affected

36. What is a static analysis and how do you perform it?
    * Inspection of source code
      * Program flow analysis
      * Constraints analysis
      * Logic tests
      * Linting
  
37. What is a dynamic analysis and how do you perform it?
    * Inspection of running software
      * Fuzzers
      * Crawlers
      * Man-in-the-middle proxy

38. What is access control and what are the aspects of it?
    * The decisions of what users are allowed to do within a system
      * Physical
      * Logical
      * Cryptographic
      * Soscial

39. What is MAC?
    * Mandatory Access Contorl
    * Access control policies decided by a central authority
    * For example OS's have MAC access over resources(CPU, memory, storage,...)

40. What is DAC?
    * Discretionary Access Control
    * Users specifies permissions for their own objects

41. What is a capability?
    * A method of only giving capabilities needed for each object

42. What are the access control models and how do they work?
    1. Access Control Lists
         * Permissions given to each object, giving different users different permissions for it
         * Each object has its own set of permissions for each user
         * Structured according to users and groups
    2. Rôle based access control
         * A set of roles abstract the permissions from the users
         * Actions are always performed by a rôle
         * Users must reauthenticate to change rôles
    3. Capability based access control
         * Users has their own capabilities  
         * A capability is a reference to an object and a set of permissions for that object
         * A capability is used whenever the resrouce is accessed

43. What is the rôle of the OS?
    * Orchestrate software
    * Communicate with programs through system calls
    * Different protections for different resources(memory, CPU, file systems, files/sockets/network connections)

44. What is the confused deputy problem?
    * A priviliedged process(deputy) is tricked by a prcoess with lower permissions, to do actions on behalf of it
    * For example comilers and browser acting as a deputy

45. What defines users and groups?
    * Each user has a UID
    * Each user is in a group that has a GID
    * Prevents users to access each others memory
    * Each file has a owner UID and a group GID

46. What are file descriptors?
    * The capabilities of accessing a file
    * Each process has its own file-descriptor table
    * OS checks permissions when opening files and creating descriptor

47. What is, and why do we use Virtual Memory Mapping?
    * Virtualize physical memory into pages and devide among processe
    * Its inconvenient to let programs use physical memory
    * Virtual memory is not decided at compile time, making guessing memory locations harder
    * Memory fragmentations gets hidden from the program

48. How does the UNIX file system devide directories?
    * Into logical parts

49. What is chroot?
    * Changing of root directory
    * Provides system virtualization

50. What is the OpenBSD pledge?
    * Mechanisms for restricting what system calls are allowed for each process

51. What is OS virtualization?
    * Abstracting away OS system calls, hardware or both to not be run directly on the OS's hardware

52. What is Linux kernel namespaces?
    * Grouping of processes so each groupt has individual:
      * Filesystem mount tables
      * Process stables
      * Network stack
      * UID tables

53. What is Docker and what mechanisms does it provide?
    * Containers
      * Runs programs separated from the OS using OS mechanisms
      * Templated by images
      * Construced and administrated through container daemon
    * Separation mechanisms
      * chroot
      * Individual namespaces to containers
      * CGroups to limit resources to containers
    * Capabilities
      * For each container
      * Abstraction through OS level restrictions
      * Only whitelisted capabilities allowed
    * Security configuration
      * Underlying OS level separation mechanisms
      * Dockered daemon attack surface
      * Security of container configuration

54. What is the principle of least priviledge?
    * No user or program should operate using the least amount of priviledge necessary to complete the job

55. How does SSH practice priviledge separation?
    * With monitors and slaves:
      * **Monitors**
        * Priviledged
        * Provides interface for slaves to perform priviledged actions
        * Validated requests
        * Performs actions on slaves behalf
      * **Slaves**
        * Unpriviledged
        * Does most of the work
        * Calls monitor when priviledged operations must be performed

56. How does one implement a Monitor/Slave pattern?
    1. Identifying priviledged operations
         * eg file access, accessing crypto keys, databases,...
    2. Separate request types
         * Information
         * Capabilites
         * Change of identity
    3. Devide into phases
         * Pre authentication
         * Post authetication
    4. Define Slave/Monitor connection
         * On connection, the service spawns a new connection between slave/monitor pair
    5. Define Slave/Master communication
         * Communicate through IPC mechanisms
           * Pipe
           * Shared memory
           * Socket-pair
    6. Mechanisms for changing of identity
    7. Retain slave state

57. What priviledged does SSHD have?
    * Diffie-Hellman
    * User validation
    * Password authentication
    * Public key authentication
    * Transferrable shared memory
    * **Priviledged operations in SSHD**:
      * Renewing crypto keys
      * Pseudo terminal creation (PTY)

58. Why doesn't increasing the password alphabet, increase security?
    * The length only grows constant with the size of the alphabet

59. What is NIST?
    * Standard for password creation
    * Allows atleast 64 characters
    * Compares passwords with lists of known password

60. What are the uses of a hash function?
    * Checksumming data
    * Data identifier
    * Hashing passwords
    * Signature verification/generation
    * Building crypto primitives

61. What is the ideal hash function?
    * Small input = large output
    * Collision free
    * One way
    * Quick to compute

62. What is a rainbow table?
    * Tool to derive password by looking at hash
    * Time-space tradeoff when creating look-up table for hash values to plaintext
    * Precomputed table for reversing crypographic functions
    * Used for cracking passwords

63. What is hashing salt?
    * A randomly generated string stored in the password hash making it harder to crack

64. What is a key derivation function?
    * Functions to derive plaintext passwords from hashes

65. What is naïve key derivation?
    * Generated byte strings placed before and after hash
    * Making the attacker guess the second string
    * Second strings works as cost parameter
  
66. What is SCrypt?
    * A maximum memory hard key derivation function

67. What is authetication?
    * The act of verifying the identity of actors in the system
  
68. What is 2FA authentication?
    * Additional authentication measures to passwords

69. What "is trust upon first use"?
    * Trust user first time they log in because it is unlikely there is a man-in-the-middle on inital authentication
    * Use this authetication for the next sessions

70. What is a CA?
    * A Central Authority trusted to verify public keys and issue certificated for the keys

71. What are the requirements for a session ID?
    * Session ID must not be guessable
    * Session ID must not be leaked

72. Why is a stram cipher mallabe?
    * Fixed input and output length
    * Same key gives same output

73. What is a keyed hash function?
    * A function producing a hash dependent on a key
    * Used to authenticate keys
    * Provides autheticity and integrity

74. What is TLS?
    * Transport Layer Security
    * Provides confidentiality, authetication and forward secrecy
    * Uses HTTPS

75. What is cross-site scripting?
    * When an attacker gets a users browser to unintentionally serve javascript to the users session

76. How can an attacker inject malicous scripts?
    * With user data visible for other users
    * URL variables
    * User data from post requests
    * Evaluating user data in client side script

77. How did the Samy Worm work?
    * MySpace protections only covered common HTML tags
    * Samy spread through CSS through any useable tag
    * Used post request to update user profiles

78. How does XSS through XML HTTP requests work?
    * Malicous scripts makes HTTP request to the current origin
    * When sucessfully injected, the attacker has the same rights as the user hijacked

79. How do you prevent XSS?
    1. Filtering input
        * Only for simple things
        * Dissallow characters
    2. Escaping output
        * HTML bodies
        * Quoted attributes
        * Unquoted attributes
        * Quoted strings in javascript
        * CSS attribute values
        * JSON data
        * Use libraries for this, do not implement yourselves
    3. Text formatting
        * HTML sanitisers
        * Use markup languages with safe conversion

80. What is CSRF?
    * Cross-site-request forgery
    * Tricks the broswer to use its session cookie to approve actions initiated by a third party site
    * Forces user to execute actions to another site than they are currently autheticated on
    * Targets state changes
    * Browser requests automatically include credentials
    * Sites have a hard time distinguishing between a forges request and a legitimate request from a user

81. What requests should be protected from CSRF?
    * Links
    * Forms
    * Pretty much all other GET/POST

82. Why should a developer not set a anti-CSRF token in a cookie and where should he place it instead?
    * Attacker could set the cookie from within the domain
    * Place token on all forms

83. What flags should be set to secure the session token?
    1. Secure
        * Sends the cookie through HTTPS only
    2. SameSite
        * Cookie is either always sent(None)
        * Only sent when the request is from the same origin(Strict)  
        * Only sendt with GET request(LAX)
    3. HttpOnly
        * Prevents stealing cookie with javascript
        * Cookie is always sendt in HTTP header, making it not available to scripts

84. What is CSP?
    * Content Security Policy
    * Set in HTTP header
    * Controls which sources content is allowed to come from
    * Limits inline scripts

85. What approaches can be used to define capabilities?
    * Enforced be a supervisor
    * Unguessable capatilities(random tokens, crypto signature,..)

86. What properties can a capability have?
    1. Transferable
       * Should be transferable between users
       * Capabilities generally dont care who uses them
    2. Abstraction
    3. Memory Safe
       * Endownment: A user might have instrisic capabilities given at creation
       * Creation: User gets capabilities to access an object he creates
       * Introduction: User transers a capability to another user
    4. Revokability
       * The creator of a capability should be able to revoke it
    5. anti-CSRF
       * Limits permissions to a specifies request type
    6. Collaboration
       * Run a program with shared capabilities to access shared resources
    7. Universal persistence
       * The state of the resource stays the same so it is never restarted

87. What is Capsicum?
    * Provides capability based security based security for UNIX programs
    * Extends the UNIX api's without replacing them or compromise performance

88. What capabilities does Capsicum provide?
    * Capabilities of file descriptors with a set of access rights
      * Around 60

89. What does capability mode in Capsicum do?
    * Restricts access to global name spaces
      * PID
      * File paths
      * POSIX IPC
      * System clocks/times

90. How does Capsicum enforce the restriction in capability mode?
    * By restricing kernel primitives
    * In capability mode, the only availabe PID is the process's own PID
    * Child processes can only be accessed through capabilities

91. What is serialization and deserialization?
    * Serialization: The process of turning objects of a programming language into byte arrays for transport
    * Deserialization: Turning transported byte arrays back into objects

92. Why is incorrect deserialization dangerous?
    * The deserialized code is at the forefront of the program. Without is being properly deserialized, it could lead to bugs and give an attacker RCE access

93. What are the entries in the secure software development cycle?
    1. Requirements
       * Map security and privacy requirements
    2. Design
       * Threat modeling
       * Security design preview
    3. Implementations
       * Static analysis
       * Peer review
    4. Testing
       * Security test cases
       * Dynamic analysis
    5. Deployment
       * Final Security review
       * Application security monitoring and response plan

94. What are the non functional requirements and what does each entry contain?
    1. **Security and privacy**
          * The program functions according to the intentions in an adverserial enviroment
    2. **Availability, capacity, performance and efficiency**
          * *Availability*
            * The proporting of time a system spends in a functional state and not in downtime
            * Do decrease downtime and increase availability:
            * Write secure software
            * Not having bugs
            * Redundance
            * Rely less on service
            * Testing
            * Scalability
          * *Capacity* 
            * The Maximum number of simultanious users/transactions*
          * *Performance and effiency*
            * The ability to increase capacity and make use of scarce resources
    3. **Extensibility, maintainability, portability and scalability**
          * *Portability*
            * The ability of the software to run on different systems with little adaptation
    4. **Recoverability**
         * How easy it is for the system to recover from disruptive events
    5. **Manageability and serviceability**
         * How easy it is to develop, deploy and maintain the code
    6. *Cohesion*
       * The degree to which parts of system/module belong together

95. What should be reviewed during a security review?
    * Security design
    * Peer review
    * Final security review before deployment

96. What aspects of program should be logged?
    * Authenticated events
    * Attempted intrusions
    * Violations of invariants
    * Unusual behaviour
    * Performance statistics

97. What is a program state and why is it important to security?
    * Program state consists of:
      * Variables
      * File descriptors
      * Cookies
      * Client storage

    * If a program reaches an unanticipated state, bugs could occur

98. What is preservation of invariants?
    * The methods of an object ensures the internal state is a valid representation

99. What is immutability?
    * An object can not be changed after creation
    * Provides security since an attacker could not change objects to alter the state

100. How can a program achieve immutability?