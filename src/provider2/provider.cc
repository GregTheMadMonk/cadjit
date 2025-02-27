module provider;

import std;

std::string_view provider_name() { return "provider2"; }

float func1(float)   { return 1; }
float func2(float x) { return 3 * x; }
float func3(float x) { return x * x * x; }
float func4(float x) { return 2 * x * x + 7 * x + 2; }

float dfunc1(float)   { return 0; }
float dfunc2(float)   { return 3; }
float dfunc3(float x) { return 3 * x * x; }
float dfunc4(float x) { return 4 * x + 7; }
