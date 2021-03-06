/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Simon Fraser <smfr@smfr.org>
 *   Josh Aas <josh@mozilla.com>
 *   Nick Kreeger <nick.kreeger@park.edu>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#import "NSWorkspace+Utils.h"

// Private and undocumented Apple API.  Generally, Launch Services uses
// CFTypes instead of NSTypes, but they're used in this file as type-equivalent
// NSTypes.  Declaring them this way avoids unsightly casts.
OSStatus _LSCopyDefaultSchemeHandlerURL(NSString* scheme, NSURL** handlerURL);
OSStatus _LSSetDefaultSchemeHandlerURL(NSString* scheme, NSURL* handlerURL);
OSStatus _LSSetWeakBindingForType(OSType type, OSType creator,
                                  CFStringRef extension, LSRolesMask role,
                                  FSRef* handlerFSRef);
OSStatus _LSSaveAndRefresh();

@implementation NSWorkspace(CaminoDefaultBrowserAdditions)

- (NSArray*)installedBrowserIdentifiers
{
  // use a set for automatic duplicate elimination
  NSMutableSet* browsersSet = [NSMutableSet setWithCapacity:10];

  // Once we are 10.4+, switch this all to LSCopyAllHandlersForURLScheme
  NSArray* apps = [(NSArray*)LSCopyApplicationURLsForURL((CFURLRef)[NSURL URLWithString:@"https:"], kLSRolesViewer) autorelease];

  // Put all the browsers IDs into a new array
  NSEnumerator *appEnumerator = [apps objectEnumerator];
  NSURL* anApp;
  while ((anApp = [appEnumerator nextObject])) {
    NSString *tmpBundleID = [self identifierForBundle:anApp];
    if (tmpBundleID)
      [browsersSet addObject:tmpBundleID];
  }
  
  // add default browser in case it hasn't been already
  NSString* currentBrowser = [self defaultBrowserIdentifier];
  if (currentBrowser)
    [browsersSet addObject:currentBrowser];
  
  return [browsersSet allObjects];
}

- (NSSet*)installedFeedViewerIdentifiers
{
  NSMutableSet* feedApps = [[[NSMutableSet alloc] init] autorelease]; 
  NSString* defaultFeedViewerID = [self defaultFeedViewerIdentifier];
  if (defaultFeedViewerID)
    [feedApps addObject:defaultFeedViewerID];
  
  NSArray* apps = [(NSArray*)LSCopyApplicationURLsForURL((CFURLRef)[NSURL URLWithString:@"feed:"], kLSRolesViewer) autorelease];
  
  NSEnumerator* appEnumerator = [apps objectEnumerator];
  NSURL* anApp;
  while ((anApp = [appEnumerator nextObject])) {
    NSString* tmpBundleID = [self identifierForBundle:anApp];
    if (tmpBundleID)
      [feedApps addObject:tmpBundleID];
  }

  // Safari on 10.3 claims to be a feed reader, but isn't really.
  NSString* safariID = @"com.apple.Safari";
  if (![NSWorkspace isTigerOrHigher] && [feedApps containsObject:safariID])
    [feedApps removeObject:safariID];
  
  return feedApps;
}

- (NSString*)defaultBrowserIdentifier
{
  return [self identifierForBundle:[self defaultBrowserURL]];
}

- (NSString*)defaultFeedViewerIdentifier
{
  return [self identifierForBundle:[self defaultFeedViewerURL]];
}

- (NSURL*)defaultBrowserURL
{
  NSURL *returnValue = nil;
  NSURL *currSetURL = nil;
  if (_LSCopyDefaultSchemeHandlerURL(@"http", &currSetURL) == noErr)
    returnValue = [currSetURL autorelease];
  if (!returnValue)
    returnValue = [self urlOfApplicationWithIdentifier:@"com.apple.safari"];

  return returnValue;
}

- (NSURL*)defaultFeedViewerURL
{
  NSURL* curViewer = nil;
  if (_LSCopyDefaultSchemeHandlerURL(@"feed", &curViewer) == noErr)
    return [curViewer autorelease];
  
  return nil;
}

- (void)setDefaultBrowserWithIdentifier:(NSString*)bundleID
{
  NSURL* browserURL = [self urlOfApplicationWithIdentifier:bundleID];
  if (browserURL)
  {
    FSRef browserFSRef;
    CFURLGetFSRef((CFURLRef)browserURL, &browserFSRef);
    
    _LSSetDefaultSchemeHandlerURL(@"http", browserURL);
    _LSSetDefaultSchemeHandlerURL(@"https", browserURL);
    _LSSetWeakBindingForType(0, 0, CFSTR("htm"),  kLSRolesAll, &browserFSRef);
    _LSSetWeakBindingForType(0, 0, CFSTR("html"), kLSRolesAll, &browserFSRef);
    _LSSetWeakBindingForType(0, 0, CFSTR("url"),  kLSRolesAll, &browserFSRef);
    _LSSaveAndRefresh();
  }
}

- (void)setDefaultFeedViewerWithIdentifier:(NSString*)bundleID
{
  NSURL* feedAppURL = [self urlOfApplicationWithIdentifier:bundleID];
  if (feedAppURL) {
    _LSSetDefaultSchemeHandlerURL(@"feed", feedAppURL);
    _LSSaveAndRefresh();
  }
}

- (NSURL*)urlOfApplicationWithIdentifier:(NSString*)bundleID
{
  NSURL* appURL = nil;
  if (LSFindApplicationForInfo(kLSUnknownCreator, (CFStringRef)bundleID, NULL, NULL, (CFURLRef*)&appURL) == noErr)
    return [appURL autorelease];

  return nil;
}

- (NSString*)identifierForBundle:(NSURL*)inBundleURL
{
  if (!inBundleURL) return nil;

  NSBundle* tmpBundle = [NSBundle bundleWithPath:[[inBundleURL path] stringByStandardizingPath]];
  if (tmpBundle)
  {
    NSString* tmpBundleID = [tmpBundle bundleIdentifier];
    if (tmpBundleID && ([tmpBundleID length] > 0)) {
      return tmpBundleID;
    }
  }
  return nil;
}

- (NSString*)displayNameForFile:(NSURL*)inFileURL
{
  NSString *name;
  LSCopyDisplayNameForURL((CFURLRef)inFileURL, (CFStringRef *)&name);
  return [name autorelease];
}

//
// +osVersionString
//
// Returns the system version string from
// /System/Library/CoreServices/SystemVersion.plist
// (as recommended by Apple).
//
+ (NSString*)osVersionString
{
  NSDictionary* versionInfo = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
  return [versionInfo objectForKey:@"ProductVersion"];
}

//
// +systemVersion
//
// Returns the host's OS version as returned by the 'sysv' gestalt selector,
// 10.x.y = 0x000010xy
//
+ (long)systemVersion
{
  static long sSystemVersion = 0;
  if (!sSystemVersion)
    Gestalt(gestaltSystemVersion, &sSystemVersion);
  return sSystemVersion;
}

//
// +isSnowLeopardOrHigher
//
// returns YES if we're on 10.6 or better
//
+ (BOOL)isSnowLeopardOrHigher
{
  return [self systemVersion] >= 0x1060;
}

//
// +isLeopardOrHigher
//
// returns YES if we're on 10.5 or better
//
+ (BOOL)isLeopardOrHigher
{
#if MAC_OS_X_VERSION_MIN_REQUIRED > MAC_OS_X_VERSION_10_4
  return YES;
#else
  return [self systemVersion] >= 0x1050;
#endif
}

//
// +isTigerOrHigher
//
// returns YES if we're on 10.4 or better
//
+ (BOOL)isTigerOrHigher
{
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_4
  return YES;
#else
  return [self systemVersion] >= 0x1040;
#endif
}

//
// +supportsSpotlight
//
// returns YES if we're running on a machine that supports spotlight (tiger or higher)
//
+ (BOOL)supportsSpotlight
{
  return [self isTigerOrHigher];
}

//
// +supportsUnifiedToolbar
//
// Returns YES if we're running on a machine that supports the unified title
// bar and toolbar window appearance (Tiger or higher).
//
+ (BOOL)supportsUnifiedToolbar
{
  return [self isTigerOrHigher];
}

@end
