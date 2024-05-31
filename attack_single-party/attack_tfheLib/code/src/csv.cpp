#include "csv.h"

/* namespaces */
using namespace std;

int load_csv_line(const string& filename, vector<int64_t>& in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);

  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    string l;
    getline(fd, l);
    if (l.empty()) {
      cerr << "[csv-error] empty csv file, please provide a valid csv file" << endl;
      ret = 0;
    }
    else {
      string w;
      stringstream s(l);
      while (getline(s, w, ',')) {
        int64_t val = boost::lexical_cast<int64_t>(w);
        in.push_back(val);
      }
      fd.close();

      /* print the obtained vector of numbers from a csv line */
      if (print_info) {
        cout << "[csv-info] loading vector from a csv input (line): " << endl;
        for (size_t i = 0; i < in.size(); ++i)
          cout << in[i] << " ";
        cout << endl;
      }
    }
  }
  return ret;
}

int load_csv_line(const string& filename, vector<double>& in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);

  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    string l;
    getline(fd, l);
    if (l.empty()) {
      cerr << "[csv-error] empty csv file, please provide a valid csv file" << endl;
      ret = 0;
    }
    else {
      string w;
      stringstream s(l);
      while (getline(s, w, ',')) {
        double val = boost::lexical_cast<double>(w);
        in.push_back(val);
      }
      fd.close();

      /* print the obtained vector of numbers from a csv line */
      if (print_info) {
        cout << "[csv-info] loading vector from a csv input (line): " << endl;
        for (size_t i = 0; i < in.size(); ++i)
          cout << in[i] << " ";
        cout << endl;
      }
    }
  }
  return ret;
}

int load_windows_csv_line(const string& filename, vector<int64_t>& in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);

  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    string l;
    getline(fd, l);
    if (l.empty()) {
      cerr << "[csv-error] empty csv file, please provide a valid csv file" << endl;
      ret = 0;
    }
    else {
      if (l[l.size() - 1] == '\r')
        l.erase(l.size() - 1);

      string w;
      stringstream s(l);
      while (getline(s, w, ',')) {
        int64_t val = boost::lexical_cast<int64_t>(w);
        in.push_back(val);
      }
      fd.close();

      /* print the obtained vector of numbers from a csv line */
      if (print_info) {
        cout << "[csv-info] loading vector from a csv input (line): " << endl;
        for (size_t i = 0; i < in.size(); ++i)
          cout << in[i] << " ";
        cout << endl;
      }
    }
  }
  return ret;
}

int load_windows_csv_line(const string& filename, vector<double>& in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);

  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    string l;
    getline(fd, l);
    if (l.empty()) {
      cerr << "[csv-error] empty csv file, please provide a valid csv file" << endl;
      ret = 0;
    }
    else {
      if (l[l.size() - 1] == '\r')
        l.erase(l.size() - 1);

      string w;
      stringstream s(l);
      while (getline(s, w, ',')) {
        double val = boost::lexical_cast<double>(w);
        in.push_back(val);
      }
      fd.close();

      /* print the obtained vector of numbers from a csv line */
      if (print_info) {
        cout << "[csv-info] loading vector from a csv input (line): " << endl;
        for (size_t i = 0; i < in.size(); ++i)
          cout << in[i] << " ";
        cout << endl;
      }
    }
  }
  return ret;
}

void string_to_number_vector(string& s, vector<int64_t> &in, bool print_info)
{
  if (in.size() > 0)
    in.clear();

  string w;

  stringstream c(s);
  while (getline(c, w, ',')) {
    int64_t val = boost::lexical_cast<int64_t>(w);
    in.push_back(val);
  }
  /* print the obtained vectors of numbers from a csv file */
  if (print_info) {
    cout << "[csv-info] converting a csv line to a vector of numbers" << endl;
    cout << "[csv-info] input line: " << s << endl;
    cout << "[csv-info] output vector: " ;
    for (size_t i = 0; i < in.size(); ++i)
      cout << in[i] << " ";
    cout << endl;
  }
}

void string_to_number_vector(string& s, vector<double> &in, bool print_info)
{
  if (in.size() > 0)
    in.clear();

  string w;

  stringstream c(s);
  while (getline(c, w, ',')) {
    double val = boost::lexical_cast<double>(w);
    in.push_back(val);
  }
  /* print the obtained vectors of numbers from a csv file */
  if (print_info) {
    cout << "[csv-info] converting a csv line to a vector of numbers" << endl;
    cout << "[csv-info] input line: " << s << endl;
    cout << "[csv-info] output vector: " ;
    for (size_t i = 0; i < in.size(); ++i)
      cout << in[i] << " ";
    cout << endl;
  }
}

int load_csv_file(const string& filename, vector<vector<int64_t>> &in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);
  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    while (!fd.eof()) {
      string l;
      getline(fd, l);
      vector<int64_t> tmp;
      string_to_number_vector(l, tmp);
      in.push_back(tmp);
    }
    fd.close();
    /* print the different csv lines */
    if (print_info) {
      cout << "[csv-info] loaded vectors from the lines of a csv file: " << endl;
      print_matrix(in);
    }
  }
  return ret;
}

int load_csv_file(const string& filename, vector<vector<double>> &in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);
  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    while (!fd.eof()) {
      string l;
      getline(fd, l);
      vector<double> tmp;
      string_to_number_vector(l, tmp);
      in.push_back(tmp);
    }
    fd.close();
    /* print the different csv lines */
    if (print_info) {
      cout << "[csv-info] loaded vectors from the lines of a csv file: " << endl;
      print_matrix(in);
    }
  }
  return ret;
}

int read_csv_file(const string& filename, vector<string> &in, bool print_info)
{
  int ret = 1;

  if (in.size() > 0)
    in.clear();

  fstream fd;
  fd.open(filename, std::fstream::in);
  if (!fd.is_open()) {
    cerr << "[csv-error] opening csv file failure" << endl;
    ret = 0;
  }
  else {
    while (!fd.eof()) {
      string l;
      getline(fd, l);
      in.push_back(l);
    }
    fd.close();
    /* print the different csv lines */
    if (print_info) {
      cout << "[csv-info] reading csv lines: " << endl;
      for (size_t i = 0; i < in.size(); ++i)
        cout << in[i] << endl;
    }
  }
  return ret;
}

int write_to_csv_file(const string& filename, vector<int64_t> &in, bool append)
{
  int ret = 1;
  ofstream fd;
  if (append)
    fd.open(filename, std::ios_base::app);
  else
    fd.open(filename);
  if (!fd.is_open()) {
    cerr << "[csv-error] could not open the csv output file" << endl;
    ret = 0;
  }
  else {
    for (size_t i = 0; i < (in.size() - 1); ++i) {
      fd << in[i] << ",";
    }
    fd << in[in.size()-1] << endl;
    fd.close();
  }
  return ret;
}

int write_to_csv_file(const string& filename, vector<double> &in, bool append)
{
  int ret = 1;
  ofstream fd;
  if (append)
    fd.open(filename, std::ios_base::app);
  else
    fd.open(filename);
  if (!fd.is_open()) {
    cerr << "[csv-error] could not open the csv output file" << endl;
    ret = 0;
  }
  else {
    for (size_t i = 0; i < (in.size() - 1); ++i) {
      fd << in[i] << ",";
    }
    fd << in[in.size()-1] << endl;
    fd.close();
  }
  return ret;
}

int convert_crlf_to_lf(char *in, char *out)
{
  int ret = 1;
  int c;
  FILE *ifp, *ofp;

  if ((ifp = fopen(in, "rb")) == NULL) {
    cout << "[csv-error] could not open input file" << endl;
    ret = 0;
  }
  else {
    if ((ofp = fopen(out, "wb")) == NULL) {
      cout << "[csv-error] could not open output file" << endl;
      fclose(ifp);
      ret = 0;
    }
    else {
      while ((c = getc(ifp)) != EOF) {
        if (c == '\r') {
          putc('\n', ofp);
          c = getc(ifp);
          if (c == EOF) break;
          if (c == '\n') continue;
        }
        putc(c, ofp);
      }
      fclose(ifp);
      fclose(ofp);
    }
  }
  return ret;
}

int convert_lf_to_crlf(char *in, char *out)
{
  int ret = 1;
  int c;
  FILE *ifp, *ofp;

  if ((ifp = fopen(in, "rb")) == NULL) {
    cout << "[csv-error] could not open input file\n" << endl;
    ret = 0;
  }
  else {
    if ((ofp = fopen(out, "wb")) == NULL) {
      cout << "[csv-error] could not open output file\n" << endl;
      fclose(ifp);
      ret = 0;
    }
    else {
      while ((c = getc(ifp)) != EOF) {
        if (c == '\n') {
          putc('\r', ofp);
          putc('\n', ofp);
          c = getc(ifp);
          if (c == EOF) break;
          if (c == '\n') continue;
        }
        putc(c, ofp);
      }
      fclose(ifp);
      fclose(ofp);
    }
  }
  return ret;
}
