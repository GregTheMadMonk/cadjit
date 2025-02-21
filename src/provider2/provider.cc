module provider;

import std;

std::string_view provider_name() { return "provider2"; }

float func1(float x) { return 1; }
float func2(float x) { return 3 * x; }
float func3(float x) { return x * x * x; }
float func4(float x) { return 2 * x * x + 7 * x + 2; }
