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
    class CouchDB < Interface
      attr_reader :astore, :nstore, :version
      
      def initialize(base_uri, username = "", password = "")
        store = RestClient::Resource.new("#{base_uri}", :user => username, :password => password)
        @version = JSON.parse(store.get(:content_type => 'application/json'))['version'].split('-').first
        @astore = RestClient::Resource.new("#{base_uri}/associations", :user => username, :password => password)
        @nstore = RestClient::Resource.new("#{base_uri}/nonces", :user => username, :password => password)
      end
      
      def cleanup
        cleanup_associations
        cleanup_nonces
      end
      
      def cleanup_associations
        # BUGBUG - this doesn't work yet.
        if version.match(/^0\.8\./)
          doc = astore["_all_docs"].get(:content_type => 'application/json')
          rows = JSON.parse(doc)['rows']
          rows.each do |row|
            doc = astore[row['id']].get(:content_type => 'application/json')
            associations = JSON.parse(doc) ; modified = false
            associations.delete('_id') ; associations.delete('_rev')
            associations.each_pair do |handle, association|
            unless association['issued'].to_i + association['lifetime'].to_i > Time.now.to_i
              associations.delete(handle) ; modified = true
            end
            store_associations(Base64.decode64(row['id']), associations) if modified
          end
        else
          doc = astore["_all_docs?include_docs=true"].get(:content_type => 'application/json')
          rows = JSON.parse(doc)['rows']
          rows.each do |associations|
            associations = associations['doc'] ; modified = false
            associations.delete('_id') ; associations.delete('_rev')
            associations.each_pair do |handle, association|
            unless association['issued'].to_i + association['lifetime'].to_i > Time.now.to_i
              associations.delete(handle) ; modified = true
            end
            store_associations(Base64.decode64(row['id']), associations) if modified
          end
        end
      end
      
      def cleanup_nonces
        if version.match(/^0\.8\./)
          doc = nstore["_all_docs"].get(:content_type => 'application/json')
          rows = JSON.parse(doc)['rows']
          rows.each do |row|
            doc = nstore[row['id']].get(:content_type => 'application/json')
            nonce = JSON.parse(doc)
            if (nonce['timestamp'].to_i - Time.now.to_i).abs > Nonce.skew
              res = nstore[row['id']].delete(:content_type => 'application/json')
            end
          end
        else
          doc = nstore["_all_docs?include_docs=true"].get(:content_type => 'application/json')
          rows = JSON.parse(doc)['rows']
          rows.each do |row|
            if (row['doc']['timestamp'].to_i - Time.now.to_i).abs > Nonce.skew
              res = nstore[row['id']].delete(:content_type => 'application/json')
            end
          end
        end
      end
      
      def get_association(server_url, handle = nil)
        associations = get_associations(server_url)
        unless associations.nil?
          if handle
            a = associations[handle]
          else
            a = associations.values.sort{ |a, b| a['issued'].to_i <=> b['issued'].to_i }[-1]
          end
          association = Association.new( a['handle'],
                                         Base64.decode64(a['secret']),
                                         a['issued'].to_i,
                                         a['lifetime'].to_i,
                                         a['assoc_type'] )
          return association unless association.expires_in == 0
        end
        nil
      end
      
      def remove_association(server_url, handle)
        associations = get_associations(server_url)
        unless associations.nil?
          if associations.has_key?(handle) && associations.delete(handle)
            store_associations(server_url, associations)
            return true
          end
        end
        false
      end
      
      def store_association(server_url, association)
        associations = get_associations(server_url)
        associations ||= {}
        associations.merge!({ association.handle => {
              :handle => association.handle,
              :secret => Base64.encode64(association.secret),
              :issued => association.issued.to_i,
              :lifetime => association.lifetime.to_i,
              :assoc_type => association.assoc_type
            }
          }
        )
        store_associations(server_url, associations)
      end
      
      def use_nonce(server_url, timestamp, salt)
        return false if (timestamp - Time.now.to_i).abs > Nonce.skew

        # this little block is from OpenID::Store::Filesystem.  i don't like it.
        if server_url and !server_url.empty?
          proto, rest = server_url.split('://', 2)
        else
          proto, rest = '',''
        end
        raise "Bad server URL" unless proto && rest

        nonce = '%08x-%s-%s'%[timestamp, Base64.encode64(server_url).chomp, Base64.encode64(salt.to_s).chomp]
        
        begin
          res = nstore[nonce].get(:content_type => 'application/json')
          return false
        rescue RestClient::ResourceNotFound => e
          res = nstore[nonce].put({ :server_url => server_url,
                                    :timestamp => timestamp,
                                    :salt => salt
                                   }.to_json, :content_type => 'application/json')
          return true
        end
      end

      protected

      def get_associations(server_url)
        begin
          doc = astore[Base64.encode64(server_url)].get(:content_type => 'application/json')
          return JSON.parse(doc)
        rescue
          nil
        end
      end

      def store_associations(server_url, associations)
        associations['_rev'] = generate_doc_version if associations['_rev']
        
        begin
          astore[Base64.encode64(server_url)].put(associations.to_json,
                                                  :content_type => 'application/json')
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