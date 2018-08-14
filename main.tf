###############################################################################
#   Copyright 2016 Cerbo.IO, LLC.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
###############################################################################

###############################################################################
# CUSTOM CONFIGURATION    #
# Let 'waf' script change #
###########################
variable "customer" {
    description = "[REQUIRED] Customer/Project Name (max 15 characters):"
    default     = "jonathancandid"
}

variable "CloudFrontAccessLogBucket" {
    description = "[REQUIRED] CDN S3 Logs Bucket:"
    default     = "jonathan-logging-candid"
}

variable "DefaultRuleAllowBlock" {
    description = "Whether to ALLOW or BLOCK traffic that does not match rules. Use BLOCK for Non-Prod environments."
    default = "ALLOW"
}

###############################################################################




###############################################################################
# CUSTOM VARIABLES - TUNNING WAF #
#   BE CAREFUL, MASSIVE IMPACT   #
##################################
#default = "50"
variable "ErrorThreshold" {
    default = "500"
}
#default = "400"
variable "RequestThreshold" {
    default = "800"
}
variable "WAFBlockPeriod" {
    default = "240"
}



###############################################################################
# TURN ON COMPONENTS #
#    DO NOT TOUCH    #
######################
variable "ActivateBadBotProtectionParam" {
    default = "yes"
}
variable "ActivateHttpFloodProtectionParam" {
    default = "yes"
}
variable "ActivateReputationListsProtectionParam" {
    default = "yes"
}
variable "ActivateScansProbesProtectionParam" {
    default = "yes"
}
variable "CrossSiteScriptingProtectionParam" {
    default = "yes"
}
variable "SqlInjectionProtectionParam" {
    default = "yes"
}



###############################################################################
# IMPROVE AWS WAF #
###################
# Helps Amazon tune WAF functionality - highly recommended
variable "SendAnonymousUsageData" {
    default = "yes"
}


###############################################################################
# REGION - us-east-1 #
######################
# Used by modules - DO NOT REMOVE!
variable "aws_region" {
    description = "AWS US-East-1 region"
    default     = "us-east-1"
}



###############################################################################
# GET AWS ACCOUNT #
###################
data "aws_caller_identity" "current" { }
output "account_id" {
    value = "${data.aws_caller_identity.current.account_id}"
}
