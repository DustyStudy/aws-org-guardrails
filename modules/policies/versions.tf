terraform {
  # 1.9 is the first release where a variable validation can reference
  # another variable (used for allowed_regions vs. partition).
  required_version = ">= 1.9"
}
