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
        std::string m_originalErrorMessage;
        std::string m_message;

        explicit FailedToSearchFileException(std::string originalErrorMessage) : m_originalErrorMessage(std::move(originalErrorMessage)) {
            m_message = "Failed to search file: " + m_originalErrorMessage;
        }

        const char* what() const noexcept override {
            return m_message.c_str();
        }
    };
}