/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HEAD_AUTH_CONNECT_HEAD
#define HEAD_AUTH_CONNECT_HEAD

#define AUTH_LOGF(fmt, ...) printf("[f:" fmt ".]\n", ##__VA_ARGS__)
#define AUTH_LOGE(fmt, ...) printf("[e:" fmt ".]\n", ##__VA_ARGS__)
#define AUTH_LOGW(fmt, ...) printf("[w:" fmt ".]\n", ##__VA_ARGS__)
#define AUTH_LOGI(fmt, ...) printf("[i:" fmt ".]\n", ##__VA_ARGS__)
#define AUTH_LOGD(fmt, ...) printf("[d:" fmt ".]\n", ##__VA_ARGS__)

// 3 minutes
#define WAIT_USER_PERMIT_TIMEOUT (60 * 3)

#define USER_PERMIT_SUCCESS                    0
#define USER_PERMIT_ERR_CON_ABILITY_FAIL     (-1)
#define USER_PERMIT_ERR_SHOW_DIALOG_FAIL     (-2)
#define USER_PERMIT_ERR_WAIT_DIALOG_FAIL     (-3)
#define USER_PERMIT_ERR_SET_AUTH_RESULT_FAIL (-5)

#endif // HEAD_AUTH_CONNECT_HEAD
