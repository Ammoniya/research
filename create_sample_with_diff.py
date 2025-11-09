#!/usr/bin/env python3
"""
Create a sample vulnerability signature with a mock unified diff
for demonstration purposes.
"""

import json

# Mock unified diff based on the provided before/after snippets
MOCK_UNIFIED_DIFF = """diff -ruN wp-fastest-cache-0.8.9.5/inc/admin.php wp-fastest-cache-0.9.0/inc/admin.php
--- wp-fastest-cache-0.8.9.5/inc/admin.php	2019-07-01 10:00:00.000000000 +0000
+++ wp-fastest-cache-0.9.0/inc/admin.php	2019-07-15 12:00:00.000000000 +0000
@@ -150,10 +150,17 @@
 			}

+			$language_negotiation_type = apply_filters('wpml_setting', false, 'language_negotiation_type');
+			if(($language_negotiation_type == 2) && $this->isPluginActive('sitepress-multilingual-cms/sitepress.php')){
+				$cache_path = '/cache/all/%{HTTP_HOST}/';
+				$disable_condition = true;
+			}else{
+				$cache_path = '/cache/all/';
+				$disable_condition = false;
+			}
+
-				$data = $data."RewriteCond %{DOCUMENT_ROOT}/".WPFC_WP_CONTENT_BASENAME."/cache/all/$1/index.html -f"."\\n";
-				$data = $data."RewriteCond %{DOCUMENT_ROOT}/".WPFC_WP_CONTENT_BASENAME."/cache/all/$1/index.html -f [or]"."\\n";
-				$data = $data."RewriteCond ".$tmp_WPFC_WP_CONTENT_DIR."/cache/all/".$this->getRewriteBase(true)."$1/index.html -f"."\\n";
-			$data = $data.'RewriteRule ^(.*) "/'.$this->getRewriteBase().WPFC_WP_CONTENT_BASENAME.'/cache/all/'.$this->getRewriteBase(true).'$1/index.html" [
+				$data = $data."RewriteCond %{DOCUMENT_ROOT}/".WPFC_WP_CONTENT_BASENAME.$cache_path."$1/index.html -f"."\\n";
+				$data = $data."RewriteCond %{DOCUMENT_ROOT}/".WPFC_WP_CONTENT_BASENAME.$cache_path."$1/index.html -f [or]"."\\n";
+				$data = $data."RewriteCond ".$tmp_WPFC_WP_CONTENT_DIR.$cache_path.$this->getRewriteBase(true)."$1/index.html -f"."\\n";
+			$data = $data.'RewriteRule ^(.*) "/'.$this->getRewriteBase().WPFC_WP_CONTENT_BASENAME.$cache_path.$this->getRewriteBase(true).'$1/index.html" [

diff -ruN wp-fastest-cache-0.8.9.5/inc/cache.php wp-fastest-cache-0.9.0/inc/cache.php
--- wp-fastest-cache-0.8.9.5/inc/cache.php	2019-07-01 10:00:00.000000000 +0000
+++ wp-fastest-cache-0.9.0/inc/cache.php	2019-07-15 12:00:00.000000000 +0000
@@ -85,6 +85,11 @@
 			    $this->cacheFilePath = str_replace('/cache/all/', '/cache/all/'.$current_language.'/', $this->cacheFilePath);
 			}

+			// for security
+			if(preg_match("/\\.{2,}/", $this->cacheFilePath)){
+				$this->cacheFilePath = false;
+			}
+
 		}else if(isset($value->prefix) && $value->prefix && ($value->type == "page")){
 			if($buffer && preg_match("/^(homepage|category|tag|post|page|archive|attachment)$/", $value->prefix)){
 				if($preg_match_rule){
diff -ruN wp-fastest-cache-0.8.9.5/js/cdn/cdn.js wp-fastest-cache-0.9.0/js/cdn/cdn.js
--- wp-fastest-cache-0.8.9.5/js/cdn/cdn.js	2019-07-01 10:00:00.000000000 +0000
+++ wp-fastest-cache-0.9.0/js/cdn/cdn.js	2019-07-15 12:00:00.000000000 +0000
@@ -245,7 +245,13 @@
 				}
 			},
 			show_button: function(button_type){
-				self.show_button("back");
+				if(current_page.attr("wpfc-cdn-page") == 2){
+					if(self.id == "maxcdn"){
+						self.show_button("back");
+					}
+				}else{
+					self.show_button("back");
+				}
 			},
 			set_cdn_values_for_update: function(res){
 				if(res.content_type){
"""

# Load the test data
with open('test_cve_data.json', 'r') as f:
    vuln_data = json.load(f)

# Add the unified diff
vuln_data['unified_diff'] = MOCK_UNIFIED_DIFF

# Save the updated data
with open('test_cve_with_unified_diff.json', 'w') as f:
    json.dump(vuln_data, f, indent=2)

print("✓ Created test_cve_with_unified_diff.json with mock unified diff")
print(f"  Unified diff size: {len(MOCK_UNIFIED_DIFF)} bytes")
