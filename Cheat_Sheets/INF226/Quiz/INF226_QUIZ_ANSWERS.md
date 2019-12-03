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

41. What are the access control models and how do they work?
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

42. What is the rôle of the OS?
    * Orchestrate software
    * Communicate with programs through system calls
    * Different protections for different resources(memory, CPU, file systems, files/sockets/network connections)

43. What is the confused deputy problem?
    * A priviliedged process(deputy) is tricked by a prcoess with lower permissions, to do actions on behalf of it
    * For example comilers and browser acting as a deputy

44. What defines users and groups?
    * Each user has a UID
    * Each user is in a group that has a GID
    * Prevents users to access each others memory
    * Each file has a owner UID and a group GID

45. What are file descriptors?
    * The capabilities of accessing a file
    * Each process has its own file-descriptor table
    * OS checks permissions when opening files and creating descriptor

46. What is, and why do we use Virtual Memory Mapping?
    * Virtualize physical memory into pages and devide among processe
    * Its inconvenient to let programs use physical memory
    * Virtual memory is not decided at compile time, making guessing memory locations harder
    * Memory fragmentations gets hidden from the program

47. How does the UNIX file system devide directories?
    * Into logical parts

48. What is chroot?
    * Changing of root directory
    * Provides system virtualization

49. What is the OpenBSD pledge?
    * Mechanisms for restricting what system calls are allowed for each process

50. What is OS virtualization?
    * Abstracting away OS system calls, hardware or both to not be run directly on the OS's hardware

51. What is Linux kernel namespaces?
    * Grouping of processes so each groupt has individual:
      * Filesystem mount tables
      * Process stables
      * Network stack
      * UID tables

52. What is Docker and what mechanisms does it provide?
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

53. What is the principle of least priviledge?
    * No user or program should operate using the least amount of priviledge necessary to complete the job

54. How does SSH practice priviledge separation?
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

55. How does one implement a Monitor/Slave pattern?
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

56. What priviledged does SSHD have?
    * Diffie-Hellman
    * User validation
    * Password authentication
    * Public key authentication
    * Transferrable shared memory
    * **Priviledged operations in SSHD**:
      * Renewing crypto keys
      * Pseudo terminal creation (PTY)

57. Why doesn't increasing the password alphabet, increase security?
    * The length only grows constant with the size of the alphabet

58. What is NIST?
    * Standard for password creation
    * Allows atleast 64 characters
    * Compares passwords with lists of known password

59. What is the ideal hash function?
    * Small input = large output
    * Collision free
    * One way
    * Quick to compute

60. 