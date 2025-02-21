module provider;

import std;

std::string_view provider_name() { return "provider1"; }

float func1(float x) { return x; }
float func2(float x) { return 2 * x; }
float func3(float x) { return x * x; }
float func4(float x) { return x * x + 4 * x + 1; }
