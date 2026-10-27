# python-ssh-log-parser

A simple command-line tool I built to parse SSH authentication logs, track failed login attempts, and quickly surface the top IP addresses trying to brute-force access. 

## Why I Built This
Coming from a C++ background, I wanted a clean Python project to practice regular expressions, file handling, and structured data aggregation using standard libraries. Instead of dealing with nested loops and manual string slicing, this tool leverages Python's built-in `re` and `Counter` modules to process logs efficiently and cleanly summarize the security data.

## Features
- **OOP Structure:** Encapsulates the parsing logic inside an `AuthLogParser` class.
- **CLI Arguments:** Uses `argparse` so you can easily pass custom log paths via the terminal.
- **Smart Aggregation:** Automatically tracks and ranks the most frequent attacking IPs.
- **Clean Error Handling:** Catches missing files or permission issues gracefully instead of crashing with a messy traceback.

## How to Run It

1. Clone the repo:
   ```bash
   git clone [https://github.com/Jesmev/python-ssh-log-parser.git](https://github.com/Jesmev/python-ssh-log-parser.git)
   cd python-ssh-log-parser
