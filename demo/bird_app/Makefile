CXX       := g++
CXX_FLAGS := -Wall -Wextra -std=c++17

BIN     := build
SRC     := bird_app.cpp ../../controlplane/libbird.cpp
INCLUDE := -I . -I ../.. -I ../../subprojects/json/include/
LIB     := lib
EXECUTABLE  := bird_app


all: $(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(SRC)
	$(CXX) $(CXX_FLAGS) $(INCLUDE) -L$(LIB) $^ -o $@

clean:
	-rm $(BIN)/*
