import csv
import sys


def parse_argv(args):
    if len(args) > 2 or len(args) == 1:
        print("Invalid arguments")
        exit(-1)
    else:
        return args[1]


def parse_data(data):
    table = {}
    for row in data:
        try:
            if row[0] in table.keys():
                tmp = table[row[0]]
                tmp[0] += int(row[4])
                tmp[1] += int(row[5])
                table[row[0]] = tmp
            else:
                table[row[0]] = [int(row[4]), int(row[5]), 0, 0]
            if row[1] in table.keys():
                tmp = table[row[1]]
                tmp[2] += int(row[4])
                tmp[3] += int(row[5])
                table[row[1]] = tmp
            else:
                table[row[1]] = [0, 0, int(row[4]), int(row[5])]
        except ValueError:
            print("Data Error in row:", row, "-> Skipped...")
            continue
    return table


def write_data(result_file_path, data):
    try:
        with open(result_file_path, "w") as outfile:
            writer = csv.writer(outfile)
            writer.writerow(["IP", "Packets received", "Bytes received", "Packets send", "Bytes send"])
            for key in data:
                writer.writerow([key, data[key][2], data[key][3], data[key][0], data[key][1]])
            print("Result was written to {}".format(result_file_path))
    except OSError:
        print("Couldn't open result file")
        exit(-1)


def main():
    input_file_path = parse_argv(sys.argv)
    try:
        with open(input_file_path, "r") as infile:
            input_data = csv.reader(infile)
            next(input_data, None)
            result_data = parse_data(input_data)
    except OSError:
        print("Input file not found")
        exit(-1)
    result_file_path = "out_" + input_file_path
    write_data(result_file_path, result_data)
    return


if __name__ == '__main__':
    main()
