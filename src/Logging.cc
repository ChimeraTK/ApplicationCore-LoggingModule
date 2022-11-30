// SPDX-FileCopyrightText: Helmholtz-Zentrum Dresden-Rossendorf, FWKE, ChimeraTK Project <chimeratk-support@desy.de>
// SPDX-License-Identifier: LGPL-3.0-or-later
#include "Logging.h"

#include "boost/date_time/posix_time/posix_time.hpp"

#include <fstream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

using namespace logging;

std::ostream& logging::operator<<(std::ostream& os, const LogLevel& level) {
  switch(level) {
    case LogLevel::DEBUG:
      os << "DEBUG::";
      break;
    case LogLevel::INFO:
      os << "INFO::";
      break;
    case LogLevel::WARNING:
      os << "WARNING::";
      break;
    case LogLevel::ERROR:
      os << "ERROR::";
      break;
    default:
      break;
  }
  return os;
}

std::string logging::getTime() {
  std::string str;
  str.append(boost::posix_time::to_simple_string(boost::posix_time::microsec_clock::local_time()) + " ");
  str.append(" -> ");
  return str;
}

Logger::Logger(
    ctk::ApplicationModule* module, const std::string& name, const std::string& description, const std::string& tag)
: VariableGroup(module, name, description),
  message(this, "message", "",
      "Message of the module to the logging System. The leading number indicates the log level "
      "(0: DEBUG, 1: INFO, 2: WARNING, 3: ERROR, 4;SILENT). A leading 5 is used internally for old messages.",
      {tag, module->getName()}),
  alias(this, "alias", "", "Alias used in the message as identifier.", {tag, module->getName()}) {}

void Logger::sendMessage(const std::string& msg, const logging::LogLevel& level) {
  if(message.isInitialised()) {
    while(!msg_buffer.empty()) {
      message = msg_buffer.front();
      message.write();
      msg_buffer.pop();
    }
    message = std::to_string(level) + msg + "\n";
    message.write();
    // set emtpy message to let the LoggingModule know that someone called writeAll() without sending a message
    message = std::to_string(logging::LogLevel::INTERNAL) + msg + "\n";
  }
  else {
    // only use the buffer until ctk initialized the process variables
    msg_buffer.push(std::to_string(level) + msg + "\n");
  }
}

void Logger::prepare() {
  // write initial value in order to bring LoggingModule to mainLoop()
  incrementDataFaultCounter(); // force data to be flagged as faulty
  message = "5";
  message.write();
  decrementDataFaultCounter(); // data validity depends on inputs
}

LoggingModule::LoggingModule(ctk::ModuleGroup* owner, const std::string& name, const std::string& description,
    const std::string& loggingTag, const std::unordered_set<std::string>& tags)
: ctk::ApplicationModule(owner, name, description, tags), _loggingTag(loggingTag) {
  auto model = dynamic_cast<ctk::ModuleGroup*>(_owner)->getModel();
  auto neighbourDir = model.visit(ctk::Model::returnDirectory, ctk::Model::getNeighbourDirectory,
      ctk::Model::returnFirstHit(ctk::Model::DirectoryProxy{}));
  auto found = neighbourDir.visitByPath(".", [&](auto sourceDir) {
    sourceDir.visit([&](auto pv) { addVariableFromModel(pv); }, ctk::Model::breadthFirstSearch,
        ctk::Model::keepProcessVariables && ctk::Model::keepTag(_loggingTag));
  });
  if(!found) {
    throw ChimeraTK::logic_error("Error during LoggingModule construction! Model is not valid.");
  }
  if(sources.empty()) {
    throw ctk::logic_error("LoggingModule did not find any module that uses a Logger. Maybe tags used by the Logger "
                           "and the LoggingModule do not match.");
  }
}

void LoggingModule::addVariableFromModel(const ctk::Model::ProcessVariableProxy& pv) {
  ctk::RegisterPath name{pv.getFullyQualifiedPath()};
  auto tag = pv.getTags();
  // check for the logging tag
  if(!tag.count(_loggingTag)) return;
  ctk::RegisterPath path(name);
  // remove variable name
  path = path--;
  bool found = false;
  for(const auto& msg : sources) {
    if(msg == path) {
      found = true;
    }
  }
  // in case PVs of the Logging module use the same tag
  if(!found && (name.endsWith("alias") || name.endsWith("message"))) {
    sources.emplace_back(MessageSource(path, this));
  }
}

void LoggingModule::broadcastMessage(std::string msg, const bool& isError) {
  if(msg.back() != '\n') {
    msg.append("\n");
  }

  std::string tmpLog = (std::string)logTail;
  if(tailLength == 0 && messageCounter > 20) {
    messageCounter--;
    tmpLog = tmpLog.substr(tmpLog.find_first_of("\n") + 1, tmpLog.length());
  }
  else if(tailLength > 0) {
    while(messageCounter >= tailLength) {
      messageCounter--;
      tmpLog = tmpLog.substr(tmpLog.find_first_of("\n") + 1, tmpLog.length());
    }
  }
  if(targetStream == 0 || targetStream == 2) {
    if(isError)
      std::cerr << msg;
    else
      std::cout << msg;
  }
  if(targetStream == 0 || targetStream == 1) {
    if(file->is_open()) {
      (*file) << msg.c_str();
      file->flush();
    }
  }
  tmpLog.append(msg);
  messageCounter++;
  logTail = tmpLog;
  logTail.write();
}

void LoggingModule::mainLoop() {
  file.reset(new std::ofstream());
  messageCounter = 0;
  std::stringstream greeter;
  greeter << getName() << " " << getTime() << "There are " << sources.size()
          << " modules registered for logging:" << std::endl;
  broadcastMessage(greeter.str());
  for(auto module = sources.begin(); module != sources.end(); module++) {
    broadcastMessage(std::string("\t - ") + module->sendingModule);
    id_list[module->_msg.getId()] = &(*module);
  }
  auto group = readAnyGroup();
  std::string msg;
  MessageSource* currentSender;
  LogLevel level;

  while(1) {
    // we skip the initial value since it is empty anyway and set in Logger::prepare
    auto id = group.readAny();
    if(id_list.count(id) == 0) {
      throw ctk::logic_error("Cannot find  element id"
                             "when updating logging variables.");
    }
    try {
      currentSender = id_list.at(id);
      msg = (std::string)(currentSender->_msg);
    }
    catch(std::out_of_range& e) {
      throw ctk::logic_error("Cannot find  element id"
                             "when updating logging variables.");
    }
    try {
      level = static_cast<LogLevel>(std::strtoul(&msg.at(0), NULL, 0));
    }
    catch(std::out_of_range& e) {
      throw ctk::logic_error("Cannot find  message level"
                             "when updating logging variables.");
    }
    // if log level is INTERNAL someone called writeAll() in a module containing the Logger -> ignore
    if(level == LogLevel::INTERNAL) {
      continue;
    }
    if(targetStream == 4) continue;
    LogLevel setLevel = static_cast<LogLevel>((uint)logLevel);
    std::string tmpStr = msg;
    // remove message level
    tmpStr = tmpStr.substr(1, tmpStr.size());
    std::stringstream ss;
    auto senderAlias = (std::string)(currentSender->_alias);
    if(senderAlias.empty()) {
      ss << level << getName() << ":" << currentSender->sendingModule << " " << getTime() << tmpStr;
    }
    else {
      ss << level << getName() << ":" << senderAlias << " " << getTime() << tmpStr;
    }
    if(targetStream == 0 || targetStream == 1) {
      if(!((std::string)logFile).empty() && !file->is_open()) {
        std::stringstream ss_file;
        file->open((std::string)logFile, std::ofstream::out | std::ofstream::app);
        if(!file->is_open() && setLevel <= LogLevel::ERROR) {
          ss_file << LogLevel::ERROR << getName() << " " << getTime()
                  << "Failed to open log file for writing: " << (std::string)logFile << std::endl;
          broadcastMessage(ss_file.str(), true);
        }
        else if(file->is_open() && setLevel <= LogLevel::INFO) {
          ss_file << LogLevel::INFO << getName() << " " << getTime()
                  << "Opened log file for writing: " << (std::string)logFile << std::endl;
          broadcastMessage(ss_file.str());
        }
      }
    }
    if(level >= setLevel) {
      if(level < LogLevel::ERROR)
        broadcastMessage(ss.str());
      else
        broadcastMessage(ss.str(), true);
    }
  }
}

void LoggingModule::terminate() {
  if((file.get() != nullptr) && (file->is_open())) file->close();
  ApplicationModule::terminate();
}
