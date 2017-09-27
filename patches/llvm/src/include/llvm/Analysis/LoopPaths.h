//===- LoopPaths.h - Enumerate paths in loops -------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements analysis which enumerates paths in loops.  In
// particular, this pass calculates all paths in loops which are of the
// following form:
//
//  - Header to backedge, with no equivalence points on the path
//  - Header to with equivalence point
//  - Equivalence point to equivalence point
//  - Equivalence point to backedge
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ANALYSIS_LOOPPATHS_H
#define LLVM_ANALYSIS_LOOPPATHS_H

#include <set>
#include <vector>
#include <queue>
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"

namespace llvm {

//===----------------------------------------------------------------------===//
// Utilities
//===----------------------------------------------------------------------===//

/// Sort loops based on nesting depth, with deeper-nested loops coming first.
/// If the depths are equal, sort based on pointer value so that distinct loops
/// with equal depths are not considered equivalent during insertion.
struct LoopNestCmp {
  bool operator() (const Loop * const &A, const Loop * const &B) {
    unsigned DepthA = A->getLoopDepth(), DepthB = B->getLoopDepth();
    if(DepthA > DepthB) return true;
    else if(DepthA < DepthB) return false;
    else return (uint64_t)A < (uint64_t)B;
  }
};

/// A loop nest, sorted by depth (deeper loops are first).
typedef std::set<Loop *, LoopNestCmp> LoopNest;

namespace LoopPathUtilities {

/// Populate a LoopNest by traversing the loop L and its children.  L *must* be
/// the outermost loop in the nest, i.e., it has a depth of 1.
void populateLoopNest(Loop *L, LoopNest &Nest);

}

//===----------------------------------------------------------------------===//
// LoopPath helper class
//===----------------------------------------------------------------------===//

/// A path through the loop, which begins/ends either on the loop's header, the
/// loop's backedge(s) or equivalence points.
class LoopPath {
private:
  /// Basic blocks that comprise the path.  Iteration over the container is
  /// equivalent to traversing the path, but container has set semantics for
  /// quick existence checks.
  SetVector<BasicBlock *> Blocks;

  /// The path begins & ends on specific instructions.  Note that Start *must*
  /// be inside the starting block and End *must* be inside the ending block.
  Instruction *Start, *End;

  /// Does the path start at the loop header?  If not, it by definition starts
  /// at an equivalence point.
  bool StartsAtHeader;

  /// Does the path end at a backedge?  If not, it by definition ends at an
  /// equivalence point.
  bool EndsAtBackedge;

public:
  LoopPath() = delete;
  LoopPath(const std::vector<BasicBlock *> &BlockVector,
           Instruction *Start, Instruction *End,
           bool StartsAtHeader, bool EndsAtBackedge);

  bool contains(BasicBlock *BB) const { return Blocks.count(BB); }

  /// Get the starting point of the path, guaranteed to be either the loop
  /// header or an equivalence point.
  BasicBlock *startBlock() const { return Blocks.front(); }
  Instruction *startInst() const { return Start; }

  /// Get the the ending point of the path, guaranteed to be either an
  /// equivalence point or a backedge.
  BasicBlock *endBlock() const { return Blocks.back(); }
  Instruction *endInst() const { return End; }

  /// Iterators over the path's blocks.
  SetVector<BasicBlock *>::iterator begin() { return Blocks.begin(); }
  SetVector<BasicBlock *>::iterator end() { return Blocks.end(); }
  SetVector<BasicBlock *>::const_iterator cbegin() const
  { return Blocks.begin(); }
  SetVector<BasicBlock *>::const_iterator cend() const
  { return Blocks.end(); }

  /// Return whether the path starts at the loop header or equivalence point.
  bool startsAtHeader() const { return StartsAtHeader; }

  /// Return whether the path ends at a backedge block or equivalence point.
  bool endsAtBackedge() const { return EndsAtBackedge; }

  /// Return whether this is a spanning path.
  bool isSpanningPath() const { return StartsAtHeader && EndsAtBackedge; }

  /// Return whether this is an equivalence point path.
  bool isEqPointPath() const { return !StartsAtHeader || !EndsAtBackedge; }

  std::string toString() const;
  void print(raw_ostream &O) const;
  void dump() const { print(dbgs()); }
};

//===----------------------------------------------------------------------===//
// Pass implementation
//===----------------------------------------------------------------------===//

/// Analyze all paths within a loop nest
class EnumerateLoopPaths : public FunctionPass {
private:
  /// All calculated paths for each analyzed loops.
  DenseMap<const Loop *, std::vector<LoopPath> > Paths;

  /// Information about the loop currently being analyzed
  Loop *CurLoop;
  BasicBlock *Header;
  SmallPtrSet<const BasicBlock *, 4> Latches;
  DenseMap<const BasicBlock *, const Loop *> SubLoopBlocks;

  /// Depth-first search traversal information for generating path objects.
  struct LoopDFSInfo {
  public:
    Instruction *Start;
    std::vector<BasicBlock *> PathBlocks;
    bool StartsAtHeader;
  };

  /// Run a depth-first search for paths in the loop starting at an instruction.
  /// Any paths found are added to the vector of paths, and new paths to explore
  /// are added to the search queue.
  void loopDFS(Instruction *I,
               LoopDFSInfo &DFSI,
               std::vector<LoopPath> &CurPaths,
               std::queue<Instruction *> &NewPaths,
               SmallPtrSet<Instruction *, 8> &NewVisited);

  /// Enumerate all paths within a loop, stored in the vector argument.
  void analyzeLoop(Loop *L, std::vector<LoopPath> &CurPaths);

public:
  static char ID;
  EnumerateLoopPaths() : FunctionPass(ID) {}

  /// Pass interface implementation.
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  bool runOnFunction(Function &F) override;

  /// Re-run analysis to enumerate paths through a loop.  Invalidates all APIs
  /// below which populate containers with paths (for this loop only).
  void rerunOnLoop(Loop *L);

  bool hasPaths(const Loop *L) const { return Paths.count(L); }

  /// Get all the paths through a loop.  Paths in the vector are ordered as
  /// they were discovered in the depth-first traversal of the loop.
  void getPaths(const Loop *L, std::vector<const LoopPath *> &P) const;

  /// Get all paths through a loop that end at a backedge.
  void getBackedgePaths(const Loop *L, std::vector<const LoopPath *> &P) const;
  void getBackedgePaths(const Loop *L, std::set<const LoopPath *> &P) const;

  /// Get all spanning paths through a loop, where a spanning path is defined
  /// as starting at the first instruction of the header of the loop and ending
  /// at the branch in a latch.
  void getSpanningPaths(const Loop *L, std::vector<const LoopPath *> &P) const;
  void getSpanningPaths(const Loop *L, std::set<const LoopPath *> &P) const;

  /// Get all the paths through the loop that begin and/or end at an
  /// equivalence point.
  void getEqPointPaths(const Loop *L, std::vector<const LoopPath *> &P) const;
  void getEqPointPaths(const Loop *L, std::set<const LoopPath *> &P) const;

  /// Get all the paths through a loop that contain a given basic block.
  void getPathsThroughBlock(Loop *L, BasicBlock *BB,
                            std::vector<const LoopPath *> &P) const;
  void getPathsThroughBlock(Loop *L, BasicBlock *BB,
                            std::set<const LoopPath *> &P) const;

  // TODO APIs to determine if basic block has spanning & equivalence point
  // paths through it
};

}

#endif

