module provider;

import std;

std::string_view provider_name() { return "provider1"; }

float func1(float x) { return x; }
float func2(float x) { return 2 * x; }
float func3(float x) { return x * x; }
float func4(float x) { return x * x + 4 * x + 1; }

float dfunc1(float)   { return 1; }
float dfunc2(float)   { return 2; }
float dfunc3(float x) { return 2 * x; }
float dfunc4(float x) { return 2 * x + 4; }
