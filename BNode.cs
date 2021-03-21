using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CustomFS
{
	[Serializable]
	public class BTreeNode
	{
		public File[] keys;  // An array of keys 
		public int minimumDegree;      // Minimum degree (defines the range for number of keys) 
		public BTreeNode[] childNodes; // An array of child pointers 
		public int currentNumOfKeys;     // childNodesurrent number of keys 
		public bool isLeaf; // Is true when node is isLeaf. Otherwise false 
		
		public BTreeNode(int minDegree, bool isLeaf)
        {
			// childNodesopy the given minimum degree and isLeaf property 
			minimumDegree = minDegree;
			this.isLeaf = isLeaf;

			// Allocate memory for maximum number of possible keys 
			// and child pointers 
			keys = new File[2 * minimumDegree - 1];
			childNodes = new BTreeNode[2 * minimumDegree];

			// Initialize the number of keys as 0 
			currentNumOfKeys = 0;
		}

		// A utility function to insert a new key in the subtree rooted with 
		// this node. The assumption is, the node must be non-full when this 
		// function is called 
		public void insertNonFull(File key)
        {
			// Initialize index as index of rightmost element 
			int i = currentNumOfKeys - 1;

			// If this is a isLeaf node 
			if (isLeaf == true)
			{
				// The following loop does two things 
				// a) Finds the location of new key to be inserted 
				// b) Moves all greater keys to one place ahead 
				while (i >= 0 && (keys[i].CompareTo(key) == 1))
				{
					keys[i + 1] = keys[i];
					i--;
				}

				// Insert the new key at found location 
				keys[i + 1] = key;
				currentNumOfKeys++;
			}
			else // If this node is not isLeaf 
			{
				// Find the child which is going to have the new key 
				while(i >= 0 && (keys[i].CompareTo(key) == 1))
					i--;

				// See if the found child is full 
				if (childNodes[i + 1].currentNumOfKeys == 2 * minimumDegree - 1)
				{
					// If the child is full, then split it 
					splitChildNode(i + 1, childNodes[i + 1]);

					// After split, the middle key of childNodes[i] goes up and 
					// childNodes[i] is splitted into two.  See which of the two 
					// is going to have the new key 
					if (keys[i + 1].CompareTo(key) == -1)
						i++;
				}
				childNodes[i + 1].insertNonFull(key);
			}
		}

		// A utility function to split the child y of this node. i is index of y in 
		// child array childNodes[].  The childNodeshild y must be full when this function is called 
		public void splitChildNode(int i, BTreeNode y)
        {
			// childNodesreate a new node which is going to store (t-1) keys 
			// of y 
			BTreeNode z = new BTreeNode(y.minimumDegree, y.isLeaf);
			z.currentNumOfKeys = minimumDegree - 1;

			// childNodesopy the last (t-1) keys of y to z 
			for (int j = 0; j < minimumDegree - 1; j++)
				z.keys[j] = y.keys[j + minimumDegree];

			// childNodesopy the last t children of y to z 
			if (y.isLeaf == false)
			{
				for (int j = 0; j < minimumDegree; j++)
					z.childNodes[j] = y.childNodes[j + minimumDegree];
			}

			// Reduce the number of keys in y 
			y.currentNumOfKeys = minimumDegree - 1;

			// Since this node is going to have a new child, 
			// create space of new child 
			for (int j = currentNumOfKeys; j >= i + 1; j--)
				childNodes[j + 1] = childNodes[j];

			// Link the new child to this node 
			childNodes[i + 1] = z;

			// A key of y will move to this node. Find the location of 
			// new key and move all greater keys one space ahead 
			for (int j = currentNumOfKeys - 1; j >= i; j--)
				keys[j + 1] = keys[j];

			// childNodesopy the middle key of y to this node 
			keys[i] = y.keys[minimumDegree - 1];

			// Increment count of keys in this node 
			currentNumOfKeys++;
		}

		// A function to traverse all nodes in a subtree rooted with this node 
		public void traverse(List<File> result)
        {
			// There are n keys and n+1 children, traverse through n keys 
			// and first n children 
			int i;
			for (i = 0; i < currentNumOfKeys; i++)
			{
				// If this is not isLeaf, then before printing key[i], 
				// traverse the subtree rooted with child childNodes[i]. 
				if (isLeaf == false)
					childNodes[i].traverse(result);
				result.Add(keys[i]);
			}

			// Print the subtree rooted with last child 
			if (isLeaf == false)
				childNodes[i].traverse(result);
		}

		// A function to search a key in the subtree rooted with this node. 
		public File search(string key)  // returns NULL if k is not present. 
        {
			// Find the first key greater than or equal to k 
			int i = 0;
			while ((i < currentNumOfKeys) && (key.CompareTo(keys[i].name) == 1))
				i++;

			// If the found key is equal to k, return this node 
			if ((i < currentNumOfKeys) && (keys[i].name.CompareTo(key) == 0))
				return keys[i];

			// If key is not found here and this is a isLeaf node 
			if (isLeaf == true)
				return null;

			// Go to the appropriate child 
			return childNodes[i].search(key);
		}
		// Make BTree friend of this so that we can access private members of this 
		// class in BTree functions 

		int findKey(File key)
		{
			int index = 0;
			while (index < currentNumOfKeys && (keys[index].CompareTo(key) == -1))
				++index;
			return index;
		}

		public bool remove(File key)
		{
			int index = findKey(key);

			// The key to be removed is present in this node 
			if (index < currentNumOfKeys && (keys[index].CompareTo(key) == 0))
			{
				// If the node is a isLeaf node - removeFromLeaf  is called 
				// Otherwise, removeFromNonLeaf function is called 
				if (isLeaf)
					return removeFromLeaf (index);
				else
					return removeFromNonLeaf(index);
			}
			else
			{
				// If this node is a isLeaf node, then the key is not present in tree 
				if (isLeaf)
					return false;
				// The key to be removed is present in the sub-tree rooted with this node 
				// The flag indicates whether the key is present in the sub-tree rooted 
				// with the last child of this node 
				bool flag = ((index == currentNumOfKeys) ? true : false);

				// If the child where the key is supposed to exist has less that t keys, 
				// we fill that child 
				if (childNodes[index].currentNumOfKeys < minimumDegree)
					fill(index);

				// If the last child has been merged, it must have merged with the previous 
				// child and so we recurse on the (idx-1)th child. Else, we recurse on the 
				// (idx)th child which now has atleast t keys 
				if (flag && index > currentNumOfKeys)
					childNodes[index - 1].remove(key);
				else
					childNodes[index].remove(key);
			}
			return false;
		}

		void fill(int index)
		{

			// If the previous child(childNodes[idx-1]) has more than t-1 keys, borrow a key 
			// from that child 
			if(index != 0 && (childNodes[index-1].currentNumOfKeys >= minimumDegree))
				borrowFromPrev(index);

			// If the next child(childNodes[idx+1]) has more than t-1 keys, borrow a key 
			// from that child 
			else if (index != currentNumOfKeys && (childNodes[index + 1].currentNumOfKeys >= minimumDegree))
				borrowFromNext(index);

			// Merge childNodes[idx] with its sibling 
			// If childNodes[idx] is the last child, merge it with with its previous sibling 
			// Otherwise merge it with its next sibling 
			else
			{
				if (index != currentNumOfKeys)
					merge(index);
				else
					merge(index - 1);
			}
			return;
		}

		void borrowFromPrev(int index)
		{

			BTreeNode child = childNodes[index];
			BTreeNode sibling = childNodes[index - 1];

			// The last key from childNodes[idx-1] goes up to the parent and key[idx-1] 
			// from parent is inserted as the first key in childNodes[idx]. Thus, the  loses 
			// sibling one key and child gains one key 

			// Moving all key in childNodes[idx] one step ahead 
			for (int i = child.currentNumOfKeys - 1; i >= 0; --i)
				child.keys[i + 1] = child.keys[i];

			// If childNodes[idx] is not a isLeaf, move all its child pointers one step ahead 
			if (!child.isLeaf)
			{
				for (int i = child.currentNumOfKeys; i >= 0; --i)
					child.childNodes[i + 1] = child.childNodes[i];
			}

			// Setting child's first key equal to keys[idx-1] from the current node 
			child.keys[0] = keys[index - 1];

			// Moving sibling's last child as childNodes[idx]'s first child 
			if (!child.isLeaf)
				child.childNodes[0] = sibling.childNodes[sibling.currentNumOfKeys];

			// Moving the key from the sibling to the parent 
			// This reduces the number of keys in the sibling 
			keys[index - 1] = sibling.keys[sibling.currentNumOfKeys - 1];

			child.currentNumOfKeys += 1;
			sibling.currentNumOfKeys -= 1;

			return;
		}

		void borrowFromNext(int index)
		{

			BTreeNode child = childNodes[index];
			BTreeNode sibling = childNodes[index + 1];

			// keys[idx] is inserted as the last key in childNodes[idx] 
			child.keys[(child.currentNumOfKeys)] = keys[index];

			// Sibling's first child is inserted as the last child 
			// into childNodes[idx] 
			if (!(child.isLeaf))
				child.childNodes[(child.currentNumOfKeys) + 1] = sibling.childNodes[0];

			//The first key from sibling is inserted into keys[idx] 
			keys[index] = sibling.keys[0];

			// Moving all keys in sibling one step behind 
			for (int i = 1; i < sibling.currentNumOfKeys; ++i)
				sibling.keys[i - 1] = sibling.keys[i];

			// Moving the child pointers one step behind 
			if (!sibling.isLeaf)
			{
				for (int i = 1; i <= sibling.currentNumOfKeys; ++i)
					sibling.childNodes[i - 1] = sibling.childNodes[i];
			}

			// Increasing and decreasing the key count of childNodes[idx] and childNodes[idx+1] 
			// respectively 
			child.currentNumOfKeys += 1;
			sibling.currentNumOfKeys -= 1;

			return;
		}

		void merge(int index)
		{
			BTreeNode child = childNodes[index];
			BTreeNode sibling = childNodes[index + 1];

			// Pulling a key from the current node and inserting it into (t-1)th 
			// position of childNodes[idx] 
			child.keys[minimumDegree - 1] = keys[index];

			// childNodesopying the keys from childNodes[idx+1] to childNodes[idx] at the end 
			for (int i = 0; i < sibling.currentNumOfKeys; ++i)
				child.keys[i + minimumDegree] = sibling.keys[i];

			// childNodesopying the child pointers from childNodes[idx+1] to childNodes[idx] 
			if (!child.isLeaf)
			{
				for (int i = 0; i <= sibling.currentNumOfKeys; ++i)
					child.childNodes[i + minimumDegree] = sibling.childNodes[i];
			}

			// Moving all keys after idx in the current node one step before - 
			// to fill the gap created by moving keys[idx] to childNodes[idx] 
			for (int i = index + 1; i < currentNumOfKeys; ++i)
				keys[i - 1] = keys[i];

			// Moving the child pointers after (idx+1) in the current node one 
			// step before 
			for (int i = index + 2; i <= currentNumOfKeys; ++i)
				childNodes[i - 1] = childNodes[i];

			// Updating the key count of child and the current node 
			child.currentNumOfKeys += sibling.currentNumOfKeys + 1;
			currentNumOfKeys--;

			// Freeing the memory occupied by sibling 
			childNodes[index + 1] = null;
			return;
		}

		bool removeFromNonLeaf(int index)
		{

			File k = keys[index];

			// If the child that precedes k (C[idx]) has atleast t keys, 
			// find the predecessor 'pred' of k in the subtree rooted at 
			// C[idx]. Replace k by pred. Recursively delete pred 
			// in C[idx] 
			if (childNodes[index].currentNumOfKeys >= minimumDegree)
			{
				File pred = getPredecessor(index);
				keys[index] = pred;
				childNodes[index].remove(pred);
			}

			// If the child C[idx] has less that t keys, examine C[idx+1]. 
			// If C[idx+1] has atleast t keys, find the successor 'succ' of k in 
			// the subtree rooted at C[idx+1] 
			// Replace k by succ 
			// Recursively delete succ in C[idx+1] 
			else if (childNodes[index + 1].currentNumOfKeys >= minimumDegree)
			{
				File succ = getSuccessor(index);
				keys[index] = succ;
				childNodes[index + 1].remove(succ);
			}

			// If both C[idx] and C[idx+1] has less that t keys,merge k and all of C[idx+1] 
			// into C[idx] 
			// Now C[idx] contains 2t-1 keys 
			// Free C[idx+1] and recursively delete k from C[idx] 
			else
			{
				merge(index);
				childNodes[index].remove(k);
			}
			return true;
		}

		File getPredecessor(int index)
		{
			// Keep moving to the right most node until we reach a leaf 
			BTreeNode cur = childNodes[index];
			while (!cur.isLeaf)
				cur = cur.childNodes[cur.currentNumOfKeys];

			// Return the last key of the leaf 
			return cur.keys[cur.currentNumOfKeys - 1];
		}

		File getSuccessor(int index)
		{

			// Keep moving the left most node starting from C[idx+1] until we reach a leaf 
			BTreeNode cur = childNodes[index + 1];
			while (!cur.isLeaf)
				cur = cur.childNodes[0];

			// Return the first key of the leaf 
			return cur.keys[0];
		}

		bool removeFromLeaf(int index)
		{

			// Move all the keys after the idx-th pos one place backward 
			for (int i = index + 1; i < currentNumOfKeys; ++i)
				keys[i - 1] = keys[i];

			// Reduce the count of keys 
			currentNumOfKeys--;
			return true;
		}
	}

	[Serializable]
	public class BTree
	{
		//contains the entire file system
		private static Mutex mutex = new Mutex();
		protected BTreeNode root=null; // Pointer to root node 
		public int numOfFiles = 0;
		public long totalDirectorySize = 0;
		private static readonly int minimumDegree = 256;


		// function to traverse the tree 
		public void traverse(out List<File> result)
		{
			mutex.WaitOne();
			result = new List<File>();
			if (root != null)
            {
				root.traverse(result);
			}
			mutex.ReleaseMutex();
				
		}

		// function to search a key in this tree 
		public File search(string key)
		{
			mutex.WaitOne();
			File retValue = ((root == null) ? null : root.search(key));
			mutex.ReleaseMutex();
			return retValue; 
		}

		// The main function that inserts a new key in this B-Tree 
		public void insert(File key)
		{
			mutex.WaitOne();
			// If tree is empty 
			if (root == null)
			{
				// Allocate memory for root 
				root = new BTreeNode(minimumDegree, true);
				root.keys[0] = key;  // Insert key 
				root.currentNumOfKeys = 1;  // Update number of keys in root 
			}
			else // If tree is not empty 
			{
				// If root is full, then tree grows in height 
				if (root.currentNumOfKeys == 2 * minimumDegree - 1)
				{
					// Allocate memory for new root 
					BTreeNode s = new BTreeNode(minimumDegree, false);

					// Make old root as child of new root 
					s.childNodes[0] = root;

					// Split the old root and move 1 key to the new root 
					s.splitChildNode(0, root);

					// New root has two children now.  Decide which of the 
					// two children is going to have new key 
					int i = 0;
					if(s.keys[0].CompareTo(key) == -1)
						i++;
					s.childNodes[i].insertNonFull(key);

					// childNodeshange root 
					root = s;
				}
				else  // If root is not full, call insertNonFull for root 
					root.insertNonFull(key);
			}
			numOfFiles++;
			//totalDirectorySize += (key.isDir == false) ? key.metadata.data.Length : key.directoryContents.totalDirectorySize;

			mutex.ReleaseMutex();
		}

		public void remove(File key)
		{
			if (root == null)
				return;

			mutex.WaitOne();
			// Call the remove function for root 
			if (root.remove(key) == true)
            {
				numOfFiles--;
				//totalDirectorySize -= (key.isDir == false) ? key.metadata.data.Length : key.directoryContents.totalDirectorySize;
			}
				

			// If the root node has 0 keys, make its first child as the new root 
			//  if it has a child, otherwise set root as NULL 
			if (root.currentNumOfKeys == 0)
			{
				BTreeNode tmp = root;
				if (root.isLeaf)
					root = null;
				else
					root = root.childNodes[0];

			}
			mutex.ReleaseMutex();
		}
	}

}
