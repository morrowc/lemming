// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "dataplane/standalone/sai/dtel.h"

#include <glog/logging.h>

#include "dataplane/standalone/sai/common.h"
#include "dataplane/standalone/sai/entry.h"

const sai_dtel_api_t l_dtel = {
    .create_dtel = l_create_dtel,
    .remove_dtel = l_remove_dtel,
    .set_dtel_attribute = l_set_dtel_attribute,
    .get_dtel_attribute = l_get_dtel_attribute,
    .create_dtel_queue_report = l_create_dtel_queue_report,
    .remove_dtel_queue_report = l_remove_dtel_queue_report,
    .set_dtel_queue_report_attribute = l_set_dtel_queue_report_attribute,
    .get_dtel_queue_report_attribute = l_get_dtel_queue_report_attribute,
    .create_dtel_int_session = l_create_dtel_int_session,
    .remove_dtel_int_session = l_remove_dtel_int_session,
    .set_dtel_int_session_attribute = l_set_dtel_int_session_attribute,
    .get_dtel_int_session_attribute = l_get_dtel_int_session_attribute,
    .create_dtel_report_session = l_create_dtel_report_session,
    .remove_dtel_report_session = l_remove_dtel_report_session,
    .set_dtel_report_session_attribute = l_set_dtel_report_session_attribute,
    .get_dtel_report_session_attribute = l_get_dtel_report_session_attribute,
    .create_dtel_event = l_create_dtel_event,
    .remove_dtel_event = l_remove_dtel_event,
    .set_dtel_event_attribute = l_set_dtel_event_attribute,
    .get_dtel_event_attribute = l_get_dtel_event_attribute,
};

sai_status_t l_create_dtel(sai_object_id_t *dtel_id, sai_object_id_t switch_id,
                           uint32_t attr_count,
                           const sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->create(SAI_OBJECT_TYPE_DTEL, dtel_id, switch_id,
                            attr_count, attr_list);
}

sai_status_t l_remove_dtel(sai_object_id_t dtel_id) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->remove(SAI_OBJECT_TYPE_DTEL, dtel_id);
}

sai_status_t l_set_dtel_attribute(sai_object_id_t dtel_id,
                                  const sai_attribute_t *attr) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->set_attribute(SAI_OBJECT_TYPE_DTEL, dtel_id, attr);
}

sai_status_t l_get_dtel_attribute(sai_object_id_t dtel_id, uint32_t attr_count,
                                  sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->get_attribute(SAI_OBJECT_TYPE_DTEL, dtel_id, attr_count,
                                   attr_list);
}

sai_status_t l_create_dtel_queue_report(sai_object_id_t *dtel_queue_report_id,
                                        sai_object_id_t switch_id,
                                        uint32_t attr_count,
                                        const sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->create(SAI_OBJECT_TYPE_DTEL_QUEUE_REPORT,
                            dtel_queue_report_id, switch_id, attr_count,
                            attr_list);
}

sai_status_t l_remove_dtel_queue_report(sai_object_id_t dtel_queue_report_id) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->remove(SAI_OBJECT_TYPE_DTEL_QUEUE_REPORT,
                            dtel_queue_report_id);
}

sai_status_t l_set_dtel_queue_report_attribute(
    sai_object_id_t dtel_queue_report_id, const sai_attribute_t *attr) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->set_attribute(SAI_OBJECT_TYPE_DTEL_QUEUE_REPORT,
                                   dtel_queue_report_id, attr);
}

sai_status_t l_get_dtel_queue_report_attribute(
    sai_object_id_t dtel_queue_report_id, uint32_t attr_count,
    sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->get_attribute(SAI_OBJECT_TYPE_DTEL_QUEUE_REPORT,
                                   dtel_queue_report_id, attr_count, attr_list);
}

sai_status_t l_create_dtel_int_session(sai_object_id_t *dtel_int_session_id,
                                       sai_object_id_t switch_id,
                                       uint32_t attr_count,
                                       const sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->create(SAI_OBJECT_TYPE_DTEL_INT_SESSION,
                            dtel_int_session_id, switch_id, attr_count,
                            attr_list);
}

sai_status_t l_remove_dtel_int_session(sai_object_id_t dtel_int_session_id) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->remove(SAI_OBJECT_TYPE_DTEL_INT_SESSION,
                            dtel_int_session_id);
}

sai_status_t l_set_dtel_int_session_attribute(
    sai_object_id_t dtel_int_session_id, const sai_attribute_t *attr) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->set_attribute(SAI_OBJECT_TYPE_DTEL_INT_SESSION,
                                   dtel_int_session_id, attr);
}

sai_status_t l_get_dtel_int_session_attribute(
    sai_object_id_t dtel_int_session_id, uint32_t attr_count,
    sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->get_attribute(SAI_OBJECT_TYPE_DTEL_INT_SESSION,
                                   dtel_int_session_id, attr_count, attr_list);
}

sai_status_t l_create_dtel_report_session(
    sai_object_id_t *dtel_report_session_id, sai_object_id_t switch_id,
    uint32_t attr_count, const sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->create(SAI_OBJECT_TYPE_DTEL_REPORT_SESSION,
                            dtel_report_session_id, switch_id, attr_count,
                            attr_list);
}

sai_status_t l_remove_dtel_report_session(
    sai_object_id_t dtel_report_session_id) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->remove(SAI_OBJECT_TYPE_DTEL_REPORT_SESSION,
                            dtel_report_session_id);
}

sai_status_t l_set_dtel_report_session_attribute(
    sai_object_id_t dtel_report_session_id, const sai_attribute_t *attr) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->set_attribute(SAI_OBJECT_TYPE_DTEL_REPORT_SESSION,
                                   dtel_report_session_id, attr);
}

sai_status_t l_get_dtel_report_session_attribute(
    sai_object_id_t dtel_report_session_id, uint32_t attr_count,
    sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->get_attribute(SAI_OBJECT_TYPE_DTEL_REPORT_SESSION,
                                   dtel_report_session_id, attr_count,
                                   attr_list);
}

sai_status_t l_create_dtel_event(sai_object_id_t *dtel_event_id,
                                 sai_object_id_t switch_id, uint32_t attr_count,
                                 const sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->create(SAI_OBJECT_TYPE_DTEL_EVENT, dtel_event_id,
                            switch_id, attr_count, attr_list);
}

sai_status_t l_remove_dtel_event(sai_object_id_t dtel_event_id) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->remove(SAI_OBJECT_TYPE_DTEL_EVENT, dtel_event_id);
}

sai_status_t l_set_dtel_event_attribute(sai_object_id_t dtel_event_id,
                                        const sai_attribute_t *attr) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->set_attribute(SAI_OBJECT_TYPE_DTEL_EVENT, dtel_event_id,
                                   attr);
}

sai_status_t l_get_dtel_event_attribute(sai_object_id_t dtel_event_id,
                                        uint32_t attr_count,
                                        sai_attribute_t *attr_list) {
  LOG(INFO) << "Func: " << __PRETTY_FUNCTION__;
  return translator->get_attribute(SAI_OBJECT_TYPE_DTEL_EVENT, dtel_event_id,
                                   attr_count, attr_list);
}