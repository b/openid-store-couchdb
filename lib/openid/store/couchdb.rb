#
# Author:: Benjamin Black (<bb@opscode.com>)
# Copyright:: Copyright (c) 2009 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'openid'
require 'openid/util'
require 'openid/store/interface'
require 'openid/association'
require 'restclient'
require 'json'
require 'base64'

module OpenID
  module Store
    class CouchDB
      attr_reader :astore, :nstore
      
      def initialize(base_uri, username = "", password = "")
        @astore = RestClient::Resource.new("#{base_uri}/associations", :user => username, :password => password)
        @nstore = RestClient::Resource.new("#{base_uri}/nonces", :user => username, :password => password)
      end
      
      def cleanup
        true
      end
      
      def cleanup_associations
        true
      end
      
      def cleanup_nonces
        true
      end
      
      def get_association(server_url, handle = nil)
        res = get_associations(server_url)
        unless res.nil?
          if handle
            a = res['associations'][handle]
          else
            a = res['associations'].first
          end
          association = Association.new a
          return association unless association.expires_in == 0
        end
        nil
      end
      
      def remove_association(server_url, handle)
        res = get_associations(server_url)
        unless res.nil?
          if res['associations'].has_key?(handle) && res['associations'].delete(handle)
            store_associations(server_url, res)
            return true
          end
        end
        false
      end
      
      def store_association(server_url, association)
        res = get_associations(server_url)
        if res.nil?
          res = { :associations => {} }
        end
        res['associations'][association.handle] = association.serialize
        store_associations(server_url, res)
      end
      
      def use_nonce(server_url, timestamp, salt)
        return false if (timestamp - Time.now.to_i).abs > Nonce.skew

        # this little block is from OpenID::Store::Filesystem.  i don't like it.
        if server_url and !server_url.empty?
          proto, rest = server_url.split('://',2)
        else
          proto, rest = '',''
        end
        raise "Bad server URL" unless proto && rest

        nonce = '%08x-%s-%s'%[timestamp, Base64.encode64(server_url).chomp, Base64.encode64(salt.to_s).chomp]
        
        begin
          res = nstore[nonce].get :content_type => 'application/json'
          return false
        rescue RestClient::ResourceNotFound => e
          res = nstore[nonce].put({ :server_url => server_url,
                                    :timestamp => timestamp,
                                    :salt => salt
                                   }.to_json, :content_type => 'application/json')
          return true
        end
      end
      
      private
      
      def get_associations(server_url)
        begin
          res = astore[Base64.encode64(server_url)].get(:content_type => 'application/json')
          return JSON.parse(res)
        rescue
          nil
        end
      end
      
      def store_associations(server_url, associations)
        res = { :_ver => generate_doc_version, :associations => associations }
        begin
          astore[Base64.encode64(server_url)].put res.to_json,
                                                  :content_type => 'application/json'
        rescue
          # BUGBUG - figure out what a version conflict looks like and recover from it
          nil
        end
      end
      
      def generate_doc_version
        t = Time.now
        (t.tv_sec * 1000000 + t.tv_usec).to_s(16)
      end
         
    end
  end
end