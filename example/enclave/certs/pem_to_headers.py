import argparse
import os

def escape_c_string_content(s):
    """Escapes characters in a string for use in a C string literal."""
    # Escape backslashes first, then double quotes
    return s.replace("\\", "\\\\").replace("\"", "\\\"")

def create_c_header(pem_file_path, header_file_path, macro_name):
    """
    Reads a PEM file and converts its content into a C header file
    defining the content as a C macro string literal. (Python 3)
    """
    try:
        with open(pem_file_path, 'r', encoding='utf-8') as f_pem:
            pem_lines_raw = f_pem.readlines()
    except FileNotFoundError:
        print(f"Error: Cannot find the specified PEM file:{pem_file_path}")
        return
    except Exception as e:
        print(f"Error: Failed to read the PEM file：{e}")
        return

    # Prepare header guard based on the output filename
    base_name = os.path.basename(header_file_path)
    header_guard_name = os.path.splitext(base_name)[0].upper()
    # Replace non-alphanumeric characters with underscore for a valid C identifier
    header_guard = "".join(c if c.isalnum() else '_' for c in header_guard_name)
    if not header_guard or not header_guard[0].isalpha() and header_guard[0] != '_':
        header_guard = "CUSTOM_" + header_guard # Ensure it starts with a letter or underscore
    header_guard += "_H"


    output_content = []
    output_content.append("// THIS FILE IS GENERATED. DO NOT EDIT.\n\n")
    output_content.append(f"#ifndef {header_guard}\n")
    output_content.append(f"#define {header_guard}\n\n")
    output_content.append(f"// PEM content from: {os.path.basename(pem_file_path)}\n")
    output_content.append(f"#define {macro_name} \\\n")

    if not pem_lines_raw:
        # Handle empty PEM file: produce an empty string macro
        output_content.append("    \"\"\n")
    else:
        num_lines = len(pem_lines_raw)
        for i, line in enumerate(pem_lines_raw):
            # Strip original newline characters (e.g., \n, \r\n) from the line
            stripped_line = line.rstrip('\r\n')
            # Escape characters for C string
            processed_line_content = escape_c_string_content(stripped_line)

            # Format the line for the C macro
            # Each line in the C string literal itself will end with \r\n
            # Each part of the C macro (except the last) ends with " \"
            if i == num_lines - 1: # Last line of PEM content
                output_content.append(f"    \"{processed_line_content}\\r\\n\"\n") # No trailing backslash for C macro continuation
            else:
                output_content.append(f"    \"{processed_line_content}\\r\\n\" \\\n")

    output_content.append(f"\n#endif // {header_guard}\n")

    try:
        with open(header_file_path, 'w', encoding='utf-8') as f_header:
            f_header.write("".join(output_content))
        print(f"Header file generated successfully：{header_file_path}")
    except Exception as e:
        print(f"Error: Failed to write the header file：{e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert a PEM file into a C header file with macro definitions (Python 3).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "input_file",
        help="Path to the input PEM file."
    )
    parser.add_argument(
        "output_file",
        help="Path to the output C header file."
    )
    parser.add_argument(
        "--macro_name",
        default="PEM_CERTIFICATE_DATA",
        help="Name of the C macro defined in the header file. (Default: PEM_CERTIFICATE_DATA）"
    )

    args = parser.parse_args()

    create_c_header(args.input_file, args.output_file, args.macro_name)
