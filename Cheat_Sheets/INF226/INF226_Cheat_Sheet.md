# INF226 Cheat Sheet
- [INF226 Cheat Sheet](#inf226-cheat-sheet)
  - [Student Knowlegde](#student-knowlegde)
  - [Requirements, assumptions and mechanisms](#requirements-assumptions-and-mechanisms)
    - [Security Definition](#security-definition)
      - [Logical Arguments](#logical-arguments)
      - [Software Security Logic](#software-security-logic)
        - [Examples of requirements](#examples-of-requirements)
        - [Examples of Mechanisms](#examples-of-mechanisms)
        - [Examples of assumptions](#examples-of-assumptions)
  - [Vulnerabilities and Exploits](#vulnerabilities-and-exploits)
    - [Vulnerability Definition](#vulnerability-definition)
    - [Vulnerability Disclosure](#vulnerability-disclosure)
    - [Exploit Definition](#exploit-definition)
    - [Remote Code Execution(RCE)](#remote-code-executionrce)
    - [Buffer Overflow](#buffer-overflow)
      - [The Call Stack](#the-call-stack)
      - [Buffer Overread](#buffer-overread)
      - [Shell-Code exploit](#shell-code-exploit)
      - [NO-OP sled](#no-op-sled)
      - [Return Oriented Programming(ROP)](#return-oriented-programmingrop)
      - [Prevention of Buffer Overflow](#prevention-of-buffer-overflow)
      - [Stack Canaries](#stack-canaries)
      - [Address Space Layout Randomisation(ASLR)](#address-space-layout-randomisationaslr)
      - [W^X(Write XOR Executeable)](#wxwrite-xor-executeable)
      - [Best Practieses to Avoid Buffer Overflow](#best-practieses-to-avoid-buffer-overflow)
      - [Memory Safety](#memory-safety)
    - [Undefined Behaviour](#undefined-behaviour)
    - [SQL Injection](#sql-injection)
      - [About SQL](#about-sql)
      - [Problems with SQL](#problems-with-sql)
      - [Preventing SQL Injections](#preventing-sql-injections)
  - [Threats to Software](#threats-to-software)
    - [STRIDE](#stride)
      - [Spoofing](#spoofing)
      - [Tampering](#tampering)
      - [Repudiation](#repudiation)
      - [Information Disclosure](#information-disclosure)
      - [Denial of Service](#denial-of-service)
      - [Elevation of Priviledge](#elevation-of-priviledge)
    - [Ranking threats (DREAD)](#ranking-threats-dread)
  - [Functional Decomposition and Threat Model](#functional-decomposition-and-threat-model)
    - [Functional Decomposition](#functional-decomposition)
    - [Threat Model](#threat-model)
      - [Threat Model Example Scenario](#threat-model-example-scenario)
  - [Trusts and Boundaries](#trusts-and-boundaries)
    - [Trust](#trust)
    - [Transport Security](#transport-security)
    - [Defence in Depth](#defence-in-depth)
    - [Trusting Trust](#trusting-trust)
      - [Trusting Compilers](#trusting-compilers)
        - [Functional Equivalence](#functional-equivalence)
        - [Detection Strategy](#detection-strategy)
  - [CVE](#cve)
    - [CNAs](#cnas)
    - [CVSS](#cvss)
      - [Base Metrics](#base-metrics)
      - [Impact Metrics](#impact-metrics)
      - [Temporal Metrics](#temporal-metrics)
  - [CWE](#cwe)
  - [NVD](#nvd)
  - [Security Tools](#security-tools)
    - [Static analysis](#static-analysis)
    - [Dynamic analysis](#dynamic-analysis)
  - [Access Control](#access-control)
    - [Access Control Aspects](#access-control-aspects)
    - [Mandatory Access Control(MAC)](#mandatory-access-controlmac)
    - [Discretionary Access Control(DAC)](#discretionary-access-controldac)
    - [Access Control Models](#access-control-models)
    - [Access Control lists](#access-control-lists)
      - [Users and Groups](#users-and-groups)
    - [Rôle Based Access Control(RBAC)](#r%c3%b4le-based-access-controlrbac)
      - [Rôle of OS](#r%c3%b4le-of-os)
    - [Capability Based Access Control](#capability-based-access-control)
      - [File Descriptors](#file-descriptors)
  - [Memory Protection](#memory-protection)
    - [Virtual Memory Mapping](#virtual-memory-mapping)
  - [File System Abstraction](#file-system-abstraction)
    - [Unix File System](#unix-file-system)
  - [System Calls](#system-calls)
    - [OpenBSD Pledge](#openbsd-pledge)
  - [OS Virtualisation](#os-virtualisation)
    - [Linux Kernel namespaces](#linux-kernel-namespaces)
    - [Docker](#docker)
      - [Containers](#containers)
      - [Separation mechanisms](#separation-mechanisms)
      - [Capabilities](#capabilities)
      - [Docker Security](#docker-security)
  - [Priviledge Separation](#priviledge-separation)
    - [Principle of Least Priviledge](#principle-of-least-priviledge)
  - [Preventing Priviledge Escalation in SSH](#preventing-priviledge-escalation-in-ssh)
    - [Privilegde Separation in SSH](#privilegde-separation-in-ssh)
    - [Implementing Monitor/Slave Pattern](#implementing-monitorslave-pattern)
      - [Identifying Priviledged Operations](#identifying-priviledged-operations)
      - [Request types](#request-types)
      - [Phases](#phases)
      - [Slave/Monitor Connection](#slavemonitor-connection)
      - [Slave/Master Communication](#slavemaster-communication)
      - [Change of Identity](#change-of-identity)
      - [Retaining Slave State](#retaining-slave-state)
    - [Priviledge in SSHD](#priviledge-in-sshd)
    - [SSH Attacker Scenario](#ssh-attacker-scenario)
  - [Passwords](#passwords)
    - [Hasing password](#hasing-password)
    - [Uses of hash functions](#uses-of-hash-functions)
    - [Hashing issues](#hashing-issues)
    - [Rainbow tables](#rainbow-tables)
    - [Salting](#salting)
    - [Key Derivation Functions](#key-derivation-functions)
      - [SCrypt](#scrypt)
      - [Other Password Guessing Prevention Measures](#other-password-guessing-prevention-measures)
  - [Authentication](#authentication)
    - [Two Factor Authentication](#two-factor-authentication)
    - [Password Recovery](#password-recovery)
    - [Centralized Certificate Authorities (CA)](#centralized-certificate-authorities-ca)
    - [Other schemes](#other-schemes)
    - [Verify Logged in Users](#verify-logged-in-users)
      - [Session IDs](#session-ids)

## Student Knowlegde

- The student has to:
  - Understand issues related to system development
  - Explain common weaknesses in software security
  - Identify common threats, risks and attack vectors
  - Know best practises to defend software

## Requirements, assumptions and mechanisms

### Security Definition

- Software security is the ability of software to function according
  to intentions in an adverserial environment.

#### Logical Arguments

- Conclusion
- Assumptions
- Deduction

#### Software Security Logic

- Identify security requirements
  - Capture the intentions of the software
  - Making requirements = spelling out our intentions
- Make assumptions about the enviroment the software until run
  - Making assumptions = spelling out our knowledge of the enviroment
- Design mechanisms satisfying the requirements given the assumptions

##### Examples of requirements

- Availability of the service
- Capacity
- Integrity of data
- Authenticity of data
- Recoverability

##### Examples of Mechanisms

- Choice of programming language
- Rate limiting
- Sanity checks on user inputs
- Access control lists
- Optimisation of algorithms
- Encryption

##### Examples of assumptions

- **Assumptions pointing towards problems:**

  - User input cannot be trusted to have property X
  - IP addresses can be spoofed
  - Computer resources are finite
  - Programmers write bugs

- **Assumptions pointing towards solutions:**
  - If the program checks the input, we know it has property X
  - An attacker cannot guess a random 128 bit number.
  - The semantics of the program.
  - The type checker is correct.
  - Internet routing is quite robust

## Vulnerabilities and Exploits

### Vulnerability Definition

- When software is in a cirumstance where the program fails to hehave according to intentions
- When the program fails to be secure

### Vulnerability Disclosure

- Should the vulnerability found be publicly disclosed?
  - How much detail?
  - Include an exploit?
  - Embargo period?
- **Stances:**
  - No disclosure: No details made public
  - Coordinated disclosure: Reveal details once the the fixes has been made
  - Full-disclosure: Full details should be publicly disclosed

### Exploit Definition

- Procedure which upon execution leads to a circumstance described a vulnerability, demonstrating the insecurity of the program

### Remote Code Execution(RCE)

- The most serious vulnerability
- Gives that attacker premission to execute code on the victims machine

### Buffer Overflow

#### The Call Stack

- Stores return address for function call
- On funciton call the pointer is pushed on the stack
- When function is down the pointer is popped from the stack

#### Buffer Overread

- Reading outside of the bounds of an array

#### Shell-Code exploit

- Fill the buffer with attackers code
- Overwrite return pointer to point to the array
- Often spawns a shell, giving the attacker RCE access to the machine

#### NO-OP sled

- When an attacker does not know the address of the buffer
- Attacker fills the buffer with NO-OPs and puts the shell at the end of buffer

#### Return Oriented Programming(ROP)

- Using preexisting code instead of uploading shell code

#### Prevention of Buffer Overflow

- Write better C code
- Static analysis
- Stack Canaries
- W^X
- Address space layout randomisation

#### Stack Canaries

- Secret value placed on the stack every time program is started
- When function returns the value, checks if return pointer has been modified
- If modified, program exits immeadiately

#### Address Space Layout Randomisation(ASLR)

- Practise of randomising the layout when allocating memory in the system
- Makes it more difficult, because attacker must guess the location of functions and libraries

#### W^X(Write XOR Executeable)

- Memory allocations gives the memory different properties

  - Writeable
  - Executeable

- OS enfoces that writeable memory cannot be executeable
  - Prevents loading shell code in writeable buffers
  - Does not prevent ROP

#### Best Practieses to Avoid Buffer Overflow

- Use memory-safe languages
- Use memory-safe abstractions in unsafe languages(e.g vectors and smart pointers in C++)
- Use the compiler
- Run Static analysers to identify bugs

#### Memory Safety

- Each part of the program is only given access to explicit memory locations they are permitted
- **Example**
  - Code from function could access:
    - Arguments from the caller
    - Local variables
    - Global variables
  - **Not** variabes of other functions
- **Breaking memory-safety:**

  - Pointer arithmetic
  - Unconstrained casting
  - No bounds-check on arrays access
  - Unsafe pointer de-allocation

- **Memory-Safe languages:**
  - Java/C#(counds check on arrays, runs in virtual machine)
  - Most scripting languages
  - Most functional Languages
- **Not Memory-Safe languages:**

  - Assembly
  - C
  - C++

- Achieving memory safety
  - Garbage collection
  - Resource allocation in initialisation(RAII) and borrows checker

### Undefined Behaviour

- When code behaves unspecified be the language standard
  - For example in C, dereffering Null

### SQL Injection

#### About SQL

- Relation databases
- Domain specific language
- Queries contructed for other languages
- Queries are constructed from user input

#### Problems with SQL

- Confusion between code and data
- Strings are used to represent data and queries

#### Preventing SQL Injections

- **Prepared Statements**
  - Statement with placeholders("?") where the user data will go later
  - Separates the user input and SQL queries sent to the server
  - Allows type checking arguments
  - Could lead to better performance

## Threats to Software

### STRIDE

- Sparks imagination when developing threat model

- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation disclosure
- **D**enial of service
- **E**levation of priviledge

#### Spoofing

- Transmissions with intentialle mislabeled source
- When a person tricks the program to think he is someone else, giving him the credentiability of someone else

- URL spoofing
  - www.apple.com/ is actually www.xn--80ak6aa92e.com/
  - Browser displays as unicode characters, making it look like the apple website

#### Tampering

- Modification of persistend data or data in transport
- Examples
  - Injecting ads, malware etc in open wifi networks webpages
  - SQL injection to tamper with database

#### Repudiation

- Denial of perfoming unauthorized operations in systems where this cannot be tranced
- Repudiate: to refuse acknowledge
- For example a E-mails spoof, an untoward email was sent by a politician to another
- Does the sender have repudiation?

#### Information Disclosure

- Access data in an unauthorized fashiong
- Debug infor on production systems
- Passwords and other sensitive information logged as part of requests

#### Denial of Service

- Rendering a service unaccessible to intended users
- Flooding the service
- Exploiting vulnerability
- DNS hijacking

#### Elevation of Priviledge

- User gains more rights within a system then expected

### Ranking threats (DREAD)

- **D**amage potential
- **R**epoducibility
- **E**xploitation
- **A**ffected users
- **D**iscoverability

## Functional Decomposition and Threat Model

### Functional Decomposition

- An overview of components of the system
- A detailed map of comunication between componenents
- Description of the function of each of the components

### Threat Model

- Applicates our assumptions about a system
- What threats (Stride) applies to each component?
- Trust relationship between components?
- Which threats apply to each relationshipt?

#### Threat Model Example Scenario

- **Assumption:** Some process on the system is misbehaving
  - e.g a buffer overflow in a service caused an attacker to gain RCE
- **Requirement:** Limit the impact of this break-in
- **Mechanisms:**

## Trusts and Boundaries

### Trust

- Is not binary
  - Can not trust HTTP requests with private info
- Is not linear
  - Different users, different relationships
- When data is communicated between component with different trust, it crosses a **boundary**

### Transport Security

- First level of security
  - E.g Sql injections can be sent over HTTPS
- Secrecy
- Authenticity
- Integrity

### Defence in Depth

- Analyse what happens when a security mechanism fails
- Are other parts affected?
- Linchpins?
- When mechanisms fails
  - Detect failure
  - Migitate failure

### Trusting Trust

- Should trusting trust be a part of threat model?
- At some point one must trust the people behind the software

#### Trusting Compilers

- Must trust the compiler to compile correctly
- A compiler could recognize code and compile backdoors
- To trust a compiler:
  - Read compiler source code
  - The circle of compilers:
    - Must trust the compiler who compiled the compiler
    - And the compiler who compiled that compiler and so on

##### Functional Equivalence

- Two programs are functionally equivalent if the output from the programs are same given the same input

##### Detection Strategy

- To test a compiler:
  - Requires independent compiler
  - ${S_{A}}$ is the source code of compiler ${A}$
  - ${E_{A}}$ the executeable of ${A}$
  - ${T}$ is a compiler independent of ${A}$
  - ${E_{T}}$ is the executeable of ${T}$
    1. Compile ${S_{A}}$ using ${E_{A}}$ to get an executable ${X}$
    2. Compile ${S_{A}}$ using ${E_{T}}$ to get an executable ${Y}$
    3. Compile ${S_{A}}$ using ${X}$ to get an executable ${V}$
    4. Compile ${S_{A}}$ using ${Y}$ to get an executable ${W}$
    5. Compare ${V}$ and ${W}$ bitwise
  - ${X}$ and ${Y}$ will be different binaries, but functionally equivalent

## CVE

    Common Vulnerabilities and Exposures

- Maintained be The Mitre Corporation
- Allows referencing vulnerabilities accross systems
- Easy to track and find vulnerabilities and fixes
- Entries consists of:
  - A unique number
    - CVE-YYYY-XXXX
  - Description
  - Public references

### CNAs

    Assigns CVE numbers

- Different scopes:
  - The Mitre Corporation(Primary CNA)
  - Distributed Weakness Filing Project(open-source projects)
  - Corporations(Google, Intel, Netflix,..)

### CVSS

    Common Vulnerability Scoring System

- Assigns score to vulnerability
- 0 to 10
- Metrics:
  - Base metrics, intrinsic properties
  - Temporal metrics, changes to the vulnerability over time
  - Enviromental metrics, specifics to the enviroment of the software

#### Base Metrics

- Access Vector
  - Local
  - Adjacent network
  - Network
- Attack complexity(High, Medium, Low)
- Authenticity(Multiple, Single, None)

#### Impact Metrics

- Rated on a scale from None/Partial/Complete impact
  - Confidentiality
  - Integreity
  - Availability

#### Temporal Metrics

     Metrics who changes over time:

- **Exploitability**
  - Unproven
  - Proof-of-concept
  - Functional
  - High
- **Remediation level**
  - Official fix
  - Temporary fix
  - Workaround
  - Unavailable
- **Report confidence**
  - Unconfirmed
  - Uncorroborated
  - Confirmed

## CWE

    Common Weakness Enumeration

- List of common weaknesses present in software
- More fine-grained then Owasp Top 10, but similar
- CWE's often given as outputs from security analysis tools
- Structured by:
  - Architecture concepts
  - Development concepts
  - Research conepts

## NVD

    National Vulnerability Database

- Contains analysis of known vulnerabilities
  - CVE numbers
  - CWE numbers
  - CVSS
  - Versions affected

## Security Tools

### Static analysis

    Inspects source code

- Program flow analysis
- Contrains analysis
- Logic tests
- Linting

### Dynamic analysis

    Inspects running software

- **Fuzzer**
  - Feeds random data in to the program to trigger anomalies
- **Crawlers**
  - Maps the attack surface of the program
- **Man-in-the-middle proxy**
  - Analyses data from normal usage

## Access Control

    Decides which users can do what

- Read/write to objects
- Perform operations(start processes, allocat memory,..)
- Grant/revoke access

### Access Control Aspects

- Physical
- Logical
- Cryptographic
- Social

### Mandatory Access Control(MAC)

    Access control policies are fixed by a central authority

- Central, non-transferable access
- Operating systems have mandatory access control over resources(cpu, memory, storage)
- In addition there are systems for implementing more MAC security:
  - SELinux
  - Linux Security Modules (AppArmor)
  - Mandatory Integrity Control on Windows (Extending ACLs)
  - Language based mechanisms (e.g. Java Security Manager)

### Discretionary Access Control(DAC)

    Users specifies premissions for their own objects

- At least some priviledges are transferable
- File systems
- E-mail
- WIFI passwords

### Access Control Models

- Access control lists
- Role based access control
- Capability based access control

### Access Control lists

- Premissions are given to each object, giving users different permissions with it
- Each object has a list of permissions assigned to different users
- Premissions structured according to **users and groups**

#### Users and Groups

- User ID (UID)
- Group ID (GID)
- A program gets a Process ID(PID) when its run
  - Prevents users accessing eachothers memory
  - Files has Owner UID and Group GID
    - Read
    - Write
    - Execute
- **SUID**
  - Set UID(SUID)
    - Process is set to file owner
  - Set GID(SGID)
    - Process is set to file group
  - Sticky-Bit
    - File can only be renamed/deleted by the files owner or root
  - Can also apply for directories, not only files

### Rôle Based Access Control(RBAC)

    A set of roles abstract the permissions from the users

- Actions are always performed by a rôle
- Users must reauthenticate to change a rôle

```haskell
                    [Role0]         -->   [Permission0]
            -->                 |
[User0]                         |
            -->                 '->
                    [Role1]         -->  [Permission1]
            -->             |
[User1]                     |
            -->             '->
                    [Role2]         -->   [Permission2]
```

- Example of usage:
  - U = {alice, bob}
  - R = {doctor, patient}
  - P = {writePerscription, withdrawMedicine}
  - RôlePerm = {(doctor,writePerscription), (patient, withdrawMedicine)}
  - UserRoles = {(alice, doctor), (bob, patient), (alice, patient)}

#### Rôle of OS

- Ochestrate processes(software)
  - Provide abstract interface for hardware(drivers)
  - Communicate with programs through **system calls**
    - Interrupts and returns control to OS
- Different protections for different resources
- **Memory**
  - Virtual memory mapping
  - Limits
- **Cpu**
  - Scheduling policy
- **File systems**
  - Permissions
  - Chroot or other restrictions
  - Quotas
- **Open files/sockets/network connections**
  - File descriptors
  - Limits

### Capability Based Access Control

    Users has capabilities

- A capability is
  - A reference to an object
  - A set of permissions for that object
- Used whenever a resource is accessed

```haskell

[User0] --> [Capability0]
            [Object0    ]
            [Read       ]

[User0] ---------------->   [Capability2]
                            [Object0    ]
                            [Read       ]
                            [Write      ]


[User0] --> [Capability2]
            [Object1    ]
            [Read       ]
            [Write      ]
```

#### File Descriptors

        File descriptors are capabilities of accessing a file

- Each process has its own file-descriptor table
- Used also for:
  - stdout/stdin/stderr
  - pipes
  - sockets(network access)

- OS checks permissions when opening files and creating descriptor
  - Can be transferred between processes
  - Recipient processs does nt need to have permission to access the file to use the file-descriptor

## Memory Protection

### Virtual Memory Mapping

- Inconvenient to let programs use physical memory

- **With virtual memory:**
  - Each program gets their own virtual address space
  - Memory locations not decided at compile time 
  - Memory fragmentation hidden from programs
  - Easy to page out to swap
- As a consequence processes cannot directly adress the memory of other processes 

- **Exceptions:**
  - Processes can allocate shared memory
  - Processes can attach them selves as a debugger for another process 

## File System Abstraction

### Unix File System

- Directories group the files into logical parts
  - /bin
  - /sbin
  - /etc
  - /dev
  - /home
  - tmp
  - ...

- Operating system can restrict access by changing root directory to a different directory with **Chroot**
  - Provides system virtualisation
  - Chroot does not however:
  - Restrict network access
  - Restrict usage of system resrouces
  - Prevent comunication between processes

## System Calls


### OpenBSD Pledge

    Mechanism restricting what system calls are allowed for each process

- Calling plegde with a list of system call groups, restricts the process from accessing most system calls not on the list

## OS Virtualisation

- In addition to manually separate priviledges using the OS's mechanisms we can:
  - Abstract away the the OS systematicalle
    - OS virtualization(Docker, FreeBSD..)
  - Abstract away hardware:
    - Full virtualization: run different ISA
    - Paravirtualization: Runs cpu instructions natively

### Linux Kernel namespaces

- Groups processes so each group has individual:
  - Filesystem mount tables
  - Process tables
  - Network stack
  - UID tables

### Docker

#### Containers

- Not virtual machines!
  - If resource not namespaced by linux kernel, it is global and can be affected by the container
- Containers are systematicalli separated using OS mechanisms
- Templated by images
  - Image constructs container
  - Predictable enviroment
- Construction and administration through container daemon

#### Separation mechanisms

- Chroot
- Namespaces
  - Gives each container individual:
    - Mount tables
    - Process tables
    - Network stack
    - UID tables
- Cgroups to limit resrouces of each container

#### Capabilities

- For each container
- Abstraction of OS level restrictions
- Whitelisted capabilities

#### Docker Security

- Divided in:
  - Underlying OS level separation mechanisms
  - Dockererd daemon attack surface
  - Security of container configuration

## Priviledge Separation 

### Principle of Least Priviledge

        Every program and every user should operate using the least amount og priviledge necessary to complete the job

## Preventing Priviledge Escalation in SSH

- **OpenSSH**
  - Part of OpenBSD project
  - Found on most unix systems
  - Secure remote access (PKI)

### Privilegde Separation in SSH

- **Monitor**
  - Priviledged
  - Provides interface for slaves to perform priviledged operations
  - Validates requests
  - Finite state machine
  - Perform actions on slaves behalf

- **Slave**
  - Unpriviledged
  - Does most of the work
  - Calls on monitor when priviledged operations must be performed

- [Encryption keys] [File system] <--> [Monitor] <--> [Slave] <--> [Client]

### Implementing Monitor/Slave Pattern

- **Goal:** Limit the amount of code running in a priviledged process

#### Identifying Priviledged Operations

        Defines a service specific monitor/slave interface

- File access
- Accessing crypto keys
- Data base access
- Spawning pseudo-terminals
- Binding to a network interface

#### Request types

- Information
- Capabilities
- Change of identy

#### Phases

- **Pre authentication**
  - Slave has as little priviledge as possible 
  - Monitor only accespts authentication from slave

- **Post authentication**
  - Slave has normal user priviledges
  - Monitor validates requests requiring additional priviledges

#### Slave/Monitor Connection

- On connection, service spawns a seperate monitor/slave pair for that connection
- Slave is created by:
    1. Changing UID and GID to unused values
    2. Chrooted into an empty, unwriteable directory
    3. Marked as P-SUGID
    4. pledge("stdio, NULL)
- Slave is given the file descriptor for the connection

#### Slave/Master Communication

- Through IPC mechanisms
  - Pipe
  - Shared memory
  - Socket-pair

#### Change of Identity

- Slave should run as normal user when autheticated
- Unix does however not support changing UID of a rpocess without UID=0
  - Solution:
    1. Terminate slave and
    2. Monitor spawns a new process with correct UID/GID
- To continue, slave sessions must be retained

#### Retaining Slave State

- To retain a slave_
  - Serialize data structures and transfer to master 
  - Allocate dynamic memory resources on memory shared with master

- When new slave is spawned:
  - Serialize data structures are passed through IPC
  - Memory shared with new slave

### Priviledge in SSHD

- **Allows:**
  - Access allow Diffie-Hellman
  - Signes a challenge with server private key to authenticate the connection
  - User validation
  - Password authentication
  - Public key authentication

- **Change of identity**
  - Data structures are serialized
  - Shared memory transferred

- **Priviledged operations in sshd**
  - In post-authentication phase:
    - Key exchange supports renewing crypto keys
    - Pseudo terminal creation (PTY)
      - Requires root permissions to change ownership of device
      - Passes file descriptor to the client

### SSH Attacker Scenario

- **Assumption**: RCE gives an attacker control over the slave
  - Possible Esclation paths:
    - **Taking over system processes**
      - Restricted by UID
      - Other slaves protected by P_SGUID
    - **System calls to change the file system**
      - Root file system empty and unwriteable
    - **Local network connections**
      - Not preventable by this mechanism
      - May abuse IP trust relationships
    - **Information Gathering**
      - System time
      - PID of process
    - **Using up system resources**
      - Fork bomb
      - Intensive computations

## Passwords

- By increasing alphabet, the length only grows constant with the size

- **Nist**
  - Require a minimum length of 8 or greater
  - Allow atleast 64 character
  - Check lists of known passwords
    - Dictionairy words
    - Repetetive characters
    - Context specific words
    - Previous breached passwords

### Hasing password

- One way(given y, difficult to find x)
- Collision free(difficult to find x and x´ such that h(x)=h(x´))
- Small input yields large difference in output
- Quick to compute

### Uses of hash functions

- Checksumming data
- Data identifier
- Hashing passwords
- Signature verification/generation
- Building crypto primitives

### Hashing issues

- Same hash for same reused password
- Hashes can be computed in a dictionairy an attacker could use to brute force the password

### Rainbow tables

- time-space tradeoff when creating look-up table for hash values -> plaintext

### Salting

- Generates random string and store it in the hash
- Harder to crack
- Does not help againt brute force attack on single password
- Unix systems use 128-bit salts

### Key Derivation Functions

- Requirements:
  - One-way
  - Collision free
  - Small input to large output
  - CPU intensive
  - Memory expensive
  - Sequential
  - **Naïve key derivation**
    - Generate random byte-strings and store it before and after hash
    - attacker must guess the second string
    - The second string works as a cost parameter

#### SCrypt

- Previous key derivation is trivially computed in paralell at no additional memory cost
- SCrypt is maximally memory hard
- **Downside:** Due to its use in crypto-currencies, fast specialized circuits for scrpyt

- r block size parameter
- N CPU/Memory cost parameter
- p parallelism parameter

#### Other Password Guessing Prevention Measures

- Rate limiting password attempts
- Proof-of-work from client

## Authentication

    The act of verifying the identity of actors in the system

### Two Factor Authentication

- Additional authetication mechanism to passwords
- Examples:
  - SMS codes
  - Print out codes
  - Time based passwords (TOTP)
  - Approval from allready authenticated device
  - Public key crypto(U2F/FIDO, WebAuth)

- Could be vulnerable to phising
- Public-key systems in browsers can prevent proxy-attacks
- WebAuthn is a new W3C standard

### Password Recovery

- **Trust upon first use**
  - Man in the middle does not strike first
  - Trust upon first session and use that as authentication for the next sessions

### Centralized Certificate Authorities (CA)

- Trust a central authority to verify public keys
- Issues ceritificates for public keys

### Other schemes

- Preexisting shared secrets
- Out-of-band communication

### Verify Logged in Users

- How do we verify the requests from a logged in user is actually consistently from the authenticated user?

#### Session IDs

- **Requires:**
  - Entropy: Session ID must not be guessable
  - Secrecy: Session ID must not be leaked

- **Entropy**
  - Finite resource on any system
  - Not all random generators are suitabe for creating session ID
    - Java.util.random for examples, is guessable by only looking at a few bytes
