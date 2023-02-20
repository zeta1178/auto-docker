from __future__ import annotations
import json
import logging
from typing import *

#!/usr/local/bin/python3
################################################################################
#
################################################################################
"""
Defines a set of classes for handling Amazon Inspector findings. The goal is
to raise an exception when the number of Inspector findings of a certain
severity exceeds a threshold for that severity.

A Python-like pseudocode use case follows::

      # Invoked by EventBridge with 'event' containing Inspector Finding dict
      finding = InspectorFinding(event)

      for resource in finding.getResource():
        raw = [ query DynamoDb for finding matching resource ARN ]
        item = ImageVulnerabilityItem(raw)

        try:
          item.digest(finding)
        except ThresholdExceeded as thrown:
          [ do something about exceeded threshold ]

Event thresholds are defined in a dict with a key of the severity level (e.g.,
critical, high, medium, low) and a numeric threshold for how many such
findings will be tolerated before an exception is raised.

Currently the thresholds are hard-coded in the ImageVunlerabilityItem._THRESHOLD
value, below.
"""

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(funcName)s %(message)s")

_LOGGER = logging.getLogger()
_LOGGER.setLevel(logging.INFO)
################################################################################
#
################################################################################
class DictionaryToObject (object):
  """
  Convert an arbitrarily nested dict to a series of DictionaryToObject objects,
  allowing values to be referenced using dot notation rather than bracket
  notation or object.get().

  :dictionary:dict - any dict, including nested dicts

  CHANGES:
  1. Properly propagate subclass rather than superclass to sub-dicts
  """
  #-----------------------------------------------------------------------------
  def __init__ (self, dictionary:dict):
    self._dictionary = dictionary
    """ See class definition """
    for key, value in dictionary.items():
      # Handle list-like values - values that are dicts become nested
      # DictionaryToObject values, other values are stored as they are
      if isinstance(value, (list, tuple)):
        setattr(self, key, [ type(self)(item)
          if isinstance(item, dict) else item for item in value ])
      # Handle non-list-like values
      else:
        # Dicts become nested DictionaryToObject objects
        if isinstance(value, dict):
          setattr(self, key, type(self)(value))
        # Other values are stored as they are
        else:
          setattr(self, key, value)
  #-----------------------------------------------------------------------------
  def __getattr__ (self, name:str) -> Any:
    """
    Display an error message and then throw an attribute error to make
    debugging deep references a little easier.
    """
    _LOGGER.error(f'420000e unknown {type(self).__name__} attribute {name}')

    raise AttributeError(name)
################################################################################
#
################################################################################
class InspectorFinding (DictionaryToObject):
  """
  Map attributes of an Amazon Inspector EventBridge event
  """
  #-----------------------------------------------------------------------------
  def getResourceList (self) -> list[str]:
    """ Return affected resources """
    return self.resources
  #-----------------------------------------------------------------------------
  def getResource (self) -> str:
    """ Generator to retrieve successive affected resources """
    for resource in self.resources:
      yield resource
  #-----------------------------------------------------------------------------
  def getFindingArn (self) -> str:
    """ Return the finding ARN """
    return self.detail.findingArn
  #-----------------------------------------------------------------------------
  def getScore (self) -> float:
    """ Return the score (derived from CVSS) """
    return float(self.detail.score)
  #-----------------------------------------------------------------------------
  def getTitle (self) -> str:
    """ Return the vulnerability title """
    return self.detail.title
  #-----------------------------------------------------------------------------
  def getSeverity (self) -> str:
    """ Return the vulnerablity severity """
    return self.detail.vendorSeverity
  #-----------------------------------------------------------------------------
  def getCveId (self) -> str:
    """ Return vulnerability CVE ID """
    return self.detail.vulnerabilityId
  #-----------------------------------------------------------------------------
  def getCvss (self) -> dict[str, Union[float, str]]:
    """ Generator to retrieve sets of CVSS details """
    for cvss in self.detail.cvss:
      yield cvss
  #-----------------------------------------------------------------------------
  def getCvssList (self) -> list[dict]:
    """ Return the entire list of CVSS details """
    return self.detail.cvss
##############################################################################
#
##############################################################################
class ThresholdExceeded (Exception):
  """
  Exception raised when ingesting a finding exceeds the threshold for that
  finding's severity.
  """
  #---------------------------------------------------------------------------
  def __init__ (self, arn:str, severity:str, count:str, threshold:str):
    """ See class definition """
    self.arn = arn
    self.severity = severity
    self.count = count
    self.threshold = threshold
    self.message = \
      f'{arn} exceeded {severity} threshold ({count} of {threshold})'

    super().__init__(self.message)
##############################################################################
#
##############################################################################
class ImageVulnerabiltyItem:
  """
  Maps an DynamoDb item containing an image ARN, and a set of vulnerability
  counts.

  NOTES:

  1. Thresholds should be defined externally and configurable
  """
  # Threshold defaults -- these are only for testing
  _THRESHOLDS = { "critical": 1, "high": 5, "medium": 25, "low": 50 }
  #--------------------------------------------------------------------------
  def __init__ (self, item:dict):
    """ See class definition """
    self.imageArn = item.get("ImageArn")
    self.critical = item.get("Critical", 0)
    self.high = item.get("High", 0)
    self.medium = item.get("Medium", 0)
    self.low = item.get("Low", 0)
  #--------------------------------------------------------------------------
  def digest (self, finding:InspectorFinding) -> tuple[str, int]:
    """ Add to the severity counters """
    severity = finding.getSeverity().lower()
    threshold = self._THRESHOLDS.get(severity)
    count = getattr(self, severity, 0) + 1

    setattr(self, severity, count)

    if count >= threshold:
      raise ThresholdExceeded(self.imageArn, severity, count, threshold)

    return severity, count

