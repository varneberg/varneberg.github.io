# INF226 QUIZ ANSWERS

1. What is the definition of security?
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
    4. Temporal metrics 
        * Metrics who changes overtime
        * Rated from:
          * Exploitability(Unproven, Proof-of-concept, Functional, High)
34. What is CWE? 
35. What is NVD?
36. What is a static analysis and how do you perform it?
37. What is a dynamic analysis and how do you perform it?
38. What is access control?
39. What is MAC?
40. What is DAC?
41. What are the access control models and how do they work?
42. What are file descriptors?