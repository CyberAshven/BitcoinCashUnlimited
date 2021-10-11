# Design and operation of the adaptive blocksize feature

## Summary

The choice of a maximum block size has historically been a divisive concept requiring repeated and possibly contensious hard
forks to effect any neeeded change.  To avoid the need for hardforks, how can we automatically let the users and miners push
up the maximum block size over time  but also prevent the maximum block size from getting so large that it becomes a potential
risk to the network?  The adaptive block size algorithm described below solves this issue.

This simple algorithm family was originally proposed here: https://medium.com/@spair/a-simple-adaptive-block-size-limit-748f7cbcfb75

## Adaptive algorithm

The main issue with any adaptive algorithm is the possiblity that it could be gamed to raise the maximum block size to such an extent
as to cause a network wide issue. To remedy this, we calculate the next maximum block size by using short and long range, "median" blocksizes from the last 90 and 365 days respectively. By using the median rather than the mean value, we prevent any one
miner from artificially causing a block size increase by simply mining occasional and very large blocks.

The adaptive alogirthm is very simple and works as follows:

1) Calculate the median block size value from the both last 90 and 365 days. If there are no complete sets of values from either
   range yet (as would happen during inial mining of the new blockchain) then use the default maximum blocksize of 100K.
2) If we have one or both median values, then take it, or take the largest of the two, and multiply by the block size multiplier
   of "10", which gives us the next maximum block size value we can mine.
3) If the caculated value from above (median * multiplyer) is still less than the default maximum size of 100K, then use the default
   value as the next maximum block size.

### Purpose and choice of median ranges

The purpose of selecting the median value from both a long and short window is to allow block sizes to
increase more rapidly than they will decrease.

The median ranges were chosen with long enough windows so that no miner could temporarily game them with the purpose
of disrupting the network.

### Purpose of the block size multiplier

In times of a sudden and short lived surge in transaction volumes it's important to still be able to mine those transactions
quickly so there are no undue delays in confirmation. We can do this by multiplying the median values with a large enough
multiplier.

### Effect on other conensus parameters

The maximum signature checks allowed per block is proportional to the maximum block size allowed (which was calculated by the adaptive algorithm), and not to the actual block size which was mined.

## Copyright

This document is placed in the public domain.
