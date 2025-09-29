#pragma once

#include <exception>
#include <string>
#include <utility>

namespace Errors {
    class FailedToOpenFileException : public std::exception {
    public:
        const char* what() const noexcept override {
            return "Failed to open file";
        }
    };

    class ConstraintNotFoundException : public std::exception {
    public:
        const char* what() const noexcept override {
            return "Constraint not found (although there are more than 2 segments)";
        }
    };

    class NoPatternsProvidedException : public std::exception {
    public:
        const char* what() const noexcept override {
            return "No patterns provided";
        }
    };

    class NoValidPatternsFoundException : public std::exception {
    public:
        const char* what() const noexcept override {
            return "No valid patterns found";
        }
    };

    class FailedToSearchFileException : public std::exception {
    public:
        std::string _originalErrorMessage;
        std::string _message;

        explicit FailedToSearchFileException(std::string originalErrorMessage) : _originalErrorMessage(std::move(originalErrorMessage)) {
            _message = "Failed to search file: " + _originalErrorMessage;
        }

        const char* what() const noexcept override {
            return _message.c_str();
        }
    };
}